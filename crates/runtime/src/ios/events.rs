//! Inbound Swift→Rust view events, hooked through the guest's live vtable.
//!
//! The bridge calls `vtable[+0x20](data, bytes, len, &out)`. The vtable is built
//! at runtime, so [`discover`] finds it in-process before swapping the slot.

#[cfg(target_vendor = "apple")]
use std::ffi::CStr;

use std::{
   cell::Cell,
   ffi::c_void,
   mem::transmute,
   panic::{
      AssertUnwindSafe,
      catch_unwind,
   },
   ptr,
   slice,
   sync::{
      Mutex,
      OnceLock,
      PoisonError,
      RwLock,
      atomic::{
         AtomicBool,
         AtomicPtr,
         Ordering,
      },
   },
};

use phoenix_hook::Image;

#[cfg(target_vendor = "apple")]
use super::layout::{
   BRIDGE as BRIDGE_VMADDR,
   GUEST_HOST_SLOT,
   PINNED_UUID,
};
use super::layout::field;

type DispatchFn = unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut c_void) -> *mut c_void;

/// A guarded read of one pointer-sized word.
pub(crate) trait MemoryReader {
   fn word(&self, addr: u64) -> Option<u64>;
}

/// Image facts needed for discovery.
pub(crate) trait ImageMap {
   fn is_code(&self, addr: u64) -> bool;
   fn pointer_slots(&self) -> Vec<(usize, u64)>;
}

impl ImageMap for Image<'_> {
   fn is_code(&self, addr: u64) -> bool {
      self.is_code(addr as usize)
   }

   fn pointer_slots(&self) -> Vec<(usize, u64)> {
      let image = self
         .segments
         .iter()
         .fold((usize::MAX, 0usize), |(lo, hi), segment| {
            (lo.min(segment.addr), hi.max(segment.addr + segment.bytes.len()))
         });
      let mut out = Vec::new();
      for segment in self.segments.iter().filter(|segment| !segment.executable) {
         let bytes = &segment.bytes;
         let mut offset = 0;
         while offset + 8 <= bytes.len() {
            let value = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
            // A GuestHost is heap-allocated, so its pointer is outside the
            // image. Filtering here keeps the expensive guarded reads to a
            // small fraction of the module's words.
            if value != 0
               && value % 8 == 0
               && !(image.0..image.1).contains(&(value as usize))
            {
               out.push((segment.addr + offset, value));
            }
            offset += 8;
         }
      }
      out
   }
}

/// A guest, its Rust trait object and the vtable slot that carries dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Guest {
   /// Slot holding the `GuestHost` instance.
   pub host_slot: u64,
   pub host:      u64,
   pub guest:     u64,
   pub trait_obj: u64,
   pub vtable:    u64,
   /// The vtable's `+0x20` slot, which is what gets swapped.
   pub slot:      u64,
   pub dispatch:  u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryError {
   /// The pinned slot was present but did not hold a guest.
   PinnedInvalid,
   NotFound,
   /// More than one structurally valid guest: refuse to guess.
   Ambiguous(usize),
}

fn validate(mem: &dyn MemoryReader, map: &dyn ImageMap, slot: u64) -> Option<Guest> {
   let host = mem.word(slot)?;
   if host == 0 || host % 8 != 0 {
      return None;
   }
   let guest = mem.word(host + field::GUEST)?;
   let trait_obj = mem.word(guest + field::TRAIT)?;
   let vtable = mem.word(trait_obj + field::TRAIT_VTABLE)?;
   // A Rust vtable holds drop, size, align, then methods. Both drop and the
   // dispatch method must be code, which rejects accidental heap structures.
   let drop = mem.word(vtable)?;
   let dispatch = mem.word(vtable + field::VTABLE_DISPATCH)?;
   if !map.is_code(drop) || !map.is_code(dispatch) {
      return None;
   }
   Some(Guest {
      host_slot: slot,
      host,
      guest,
      trait_obj,
      vtable,
      slot: vtable + field::VTABLE_DISPATCH,
      dispatch,
   })
}

/// Finds the live guest; `pinned_slot` is used when the UUID matches.
pub(crate) fn discover(
   mem: &dyn MemoryReader,
   map: &dyn ImageMap,
   pinned_slot: Option<u64>,
) -> Result<Guest, DiscoveryError> {
   if let Some(slot) = pinned_slot
      && let Some(guest) = validate(mem, map, slot)
   {
      return Ok(guest);
   }
   let mut found = Vec::new();
   for (slot, _) in map.pointer_slots() {
      if let Some(guest) = validate(mem, map, slot as u64)
         && !found.iter().any(|other: &Guest| other.host == guest.host)
      {
         found.push(guest);
      }
   }
   match found.len() {
      0 => Err(if pinned_slot.is_some() {
         DiscoveryError::PinnedInvalid
      } else {
         DiscoveryError::NotFound
      }),
      1 => Ok(found[0]),
      n => Err(DiscoveryError::Ambiguous(n)),
   }
}

// ---------------------------------------------------------------------------
// Live process plumbing (Apple only; host tests use the traits above).
// ---------------------------------------------------------------------------

#[cfg(target_vendor = "apple")]
extern "C" {
   fn mach_task_self() -> u32;
   fn vm_read_overwrite(
      task: u32,
      address: u64,
      data_count: u64,
      data: *mut u8,
      data_out: *mut u64,
   ) -> i32;
   fn _dyld_image_count() -> u32;
   fn _dyld_get_image_header(index: u32) -> *const c_void;
   fn _dyld_get_image_name(index: u32) -> *const std::os::raw::c_char;
   fn _dyld_get_image_slide(header: *const c_void) -> isize;
}

#[cfg(target_vendor = "apple")]
struct ProcessMemory;

#[cfg(target_vendor = "apple")]
impl MemoryReader for ProcessMemory {
   fn word(&self, addr: u64) -> Option<u64> {
      let mut word = 0u64;
      let mut read = 0u64;
      // SAFETY: the read goes to our own task and writes only `word`/`read`.
      let status = unsafe {
         vm_read_overwrite(
            mach_task_self(),
            addr,
            8,
            (&raw mut word).cast(),
            &raw mut read,
         )
      };
      (status == 0 && read == 8).then_some(word)
   }
}

/// ASLR slide of the image whose path `Image::loaded` recorded.
#[cfg(target_vendor = "apple")]
fn slide_of(image: &Image<'_>) -> Option<isize> {
   // SAFETY: dyld's queries take an index below the count it just returned.
   unsafe {
      let count = _dyld_image_count();
      for index in 0..count {
         let name = _dyld_get_image_name(index);
         if name.is_null() {
            continue;
         }
         if CStr::from_ptr(name).to_string_lossy() == image.path {
            return Some(_dyld_get_image_slide(_dyld_get_image_header(index)));
         }
      }
   }
   None
}

struct Bridge {
   guest:    Guest,
   original: DispatchFn,
}

/// Published before the swap so the trampoline can find the original.
static BRIDGE: AtomicPtr<Bridge> = AtomicPtr::new(ptr::null_mut());
static READY: AtomicBool = AtomicBool::new(false);
static PREPARED: OnceLock<&'static Image<'static>> = OnceLock::new();
static ENSURING: AtomicBool = AtomicBool::new(false);

/// Remembers the target image for lazy discovery.
pub fn prepare(image: &'static Image<'static>) {
   let _ = PREPARED.set(image);
}

pub fn installed() -> bool {
   READY.load(Ordering::Acquire)
}

#[cfg(target_vendor = "apple")]
fn ensure_installed() {
   if installed() || ENSURING.swap(true, Ordering::AcqRel) {
      return;
   }
   let installed_guest = (|| {
      let image = *PREPARED.get()?;
      let slide = slide_of(image)?;
      let uuid = image.build_id.map(|id| id.to_string());
      let pinned = (uuid.as_deref() == Some(PINNED_UUID))
         .then(|| usize::try_from(slide).ok()?.checked_add(GUEST_HOST_SLOT))
         .flatten()
         .map(|slot| slot as u64);
      let guest = match discover(&ProcessMemory, image, pinned) {
         Ok(guest) => guest,
         Err(err) => {
            log::error!(
               "events: no guest vtable for {} ({err:?}); the bridge stays uninstalled",
               uuid.as_deref().unwrap_or("unknown build")
            );
            return None;
         },
      };
      // The bridge function itself is only a cross-check: a discovered
      // dispatch target must live in the same executable image.
      if !image.is_code(BRIDGE_VMADDR.wrapping_add_signed(slide)) {
         log::warn!("events: bridge cross-check did not resolve, continuing with the live vtable");
      }
      // SAFETY: `dispatch` came from a vtable slot in the app's own image that
      // discovery checked for code.
      let original = unsafe { transmute::<u64, DispatchFn>(guest.dispatch) };
      let bridge = Box::into_raw(Box::new(Bridge { guest, original }));
      // Publish the original before the swap: another thread can enter the
      // trampoline as soon as the slot changes.
      if BRIDGE
         .compare_exchange(ptr::null_mut(), bridge, Ordering::AcqRel, Ordering::Acquire)
         .is_err()
      {
         // SAFETY: `bridge` was just allocated and never published.
         unsafe { drop(Box::from_raw(bridge)) };
         return None;
      }
      let writes = [(guest.slot as usize, trampoline as *const () as usize)];
      // SAFETY: the slot is a pointer-aligned word in a mapped data page;
      // `swap_words` makes it writable only for the atomic exchange.
      let previous = unsafe { phoenix_hook::swap_words(&writes) }.ok();
      let agrees = previous
         .as_ref()
         .and_then(|words| words.first().copied())
         == Some(guest.dispatch as usize);
      if !agrees {
         // Restore a slot we did not understand rather than leave a stray hook.
         let _ = unsafe {
            phoenix_hook::swap_words(&[(guest.slot as usize, guest.dispatch as usize)])
         };
         BRIDGE.store(ptr::null_mut(), Ordering::Release);
         // A thread may already have loaded the bridge pointer in the swap
         // window. Leak it once rather than risk a use-after-free.
         log::error!("events: the vtable slot changed during discovery, hook not installed");
         return None;
      }
      READY.store(true, Ordering::Release);
      Some(guest)
   })();
   if let Some(guest) = installed_guest {
      log::info!(
         "events: hooked guest dispatch at {:#x} (vtable {:#x})",
         guest.dispatch,
         guest.vtable
      );
   }
   ENSURING.store(false, Ordering::Release);
}

/// Host builds have no dyld; discovery is tested through the traits above.
#[cfg(not(target_vendor = "apple"))]
fn ensure_installed() {
   log::debug!("events: bridge installation is iOS-only");
}

// ---------------------------------------------------------------------------
// Sinks and the trampoline.
// ---------------------------------------------------------------------------

/// What to do with one inbound view-event frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
   Pass,
   /// Report the frame as handled without calling the guest.
   Drop,
   /// Call the guest with `bytes` instead of the original frame.
   Replace(Vec<u8>),
}

/// Receives every view event that crosses the Swift→Rust bridge.
pub trait EventSink: Send + Sync {
   fn dispatch(&self, frame: &[u8]) -> Action;
}

pub struct EventHooks {
   hooks:    RwLock<Vec<Box<dyn EventSink>>>,
   watching: AtomicBool,
}

impl EventHooks {
   #[must_use]
   pub const fn new() -> Self {
      Self {
         hooks:    RwLock::new(Vec::new()),
         watching: AtomicBool::new(false),
      }
   }

   pub fn install(&self, sink: Box<dyn EventSink>) {
      self.hooks
         .write()
         .unwrap_or_else(PoisonError::into_inner)
         .push(sink);
      self.watching.store(true, Ordering::Release);
   }

   #[must_use]
   pub fn watching(&self) -> bool {
      self.watching.load(Ordering::Acquire)
   }

   /// Runs sinks in install order, catching panics.
   pub fn apply(&self, frame: &[u8]) -> Action {
      if !self.watching() {
         return Action::Pass;
      }
      let hooks = self
         .hooks
         .read()
         .unwrap_or_else(PoisonError::into_inner);
      let mut replaced: Option<Vec<u8>> = None;
      for sink in hooks.iter() {
         let current = replaced.as_deref().unwrap_or(frame);
         match catch_unwind(AssertUnwindSafe(|| sink.dispatch(current))) {
            Ok(Action::Drop) => return Action::Drop,
            Ok(Action::Replace(bytes)) => replaced = Some(bytes),
            Ok(Action::Pass) | Err(_) => {},
         }
      }
      replaced.map_or(Action::Pass, Action::Replace)
   }
}

impl Default for EventHooks {
   fn default() -> Self {
      Self::new()
   }
}

pub static HOOKS: EventHooks = EventHooks::new();

/// Adds an event sink and installs the hook on first use.
pub fn add_sink(sink: Box<dyn EventSink>) {
   HOOKS.install(sink);
   ensure_installed();
}

thread_local! {
   static IN_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

static DEFERRED: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// Queues a frame for the next guest dispatch; false when not installed.
pub fn dispatch_deferred(frame: Vec<u8>) -> bool {
   if !installed() {
      return false;
   }
   DEFERRED
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .push(frame);
   true
}

fn take_deferred() -> Vec<Vec<u8>> {
   std::mem::take(&mut *DEFERRED.lock().unwrap_or_else(PoisonError::into_inner))
}

/// Drops the guest's result through its vtable drop slot.
unsafe fn consume_result(result: *mut c_void) {
   if result.is_null() {
      return;
   }
   // SAFETY: `result` was returned by the guest's dispatch function.
   let vtable = unsafe { *(result as *const *const usize) };
   if vtable.is_null() {
      return;
   }
   let drop = unsafe { *vtable };
   if drop != 0 {
      // SAFETY: the guest's result is a trait object; word 0 of its vtable is
      // the drop glue, exactly as in `FUN_044b80b8` at 0x44b8104.
      let drop = unsafe { transmute::<usize, unsafe extern "C" fn(*mut c_void)>(drop) };
      unsafe { drop(result) };
   }
}

unsafe extern "C" fn trampoline(
   data: *mut c_void,
   bytes: *const u8,
   len: usize,
   out: *mut c_void,
) -> *mut c_void {
   let Some(bridge) = (unsafe { BRIDGE.load(Ordering::Acquire).as_ref() }) else {
      return ptr::null_mut();
   };
   // A nested dispatch (for example a sink feeding Phoenix an event) bypasses
   // the sinks, like the gateway's IN_JS / HANDLING guards.
   if IN_DISPATCH.get() {
      return unsafe { (bridge.original)(data, bytes, len, out) };
   }
   let called = Cell::new(false);
   let result = Cell::new(ptr::null_mut());
   let outcome = catch_unwind(AssertUnwindSafe(|| {
      IN_DISPATCH.set(true);
      for frame in take_deferred() {
         // Reuse the caller's out buffer: its size is correct by construction,
         // while a locally sized guess could be overrun by the guest.
         let returned = unsafe { (bridge.original)(data, frame.as_ptr(), frame.len(), out) };
         unsafe { consume_result(returned) };
      }
      let frame = if len == 0 || bytes.is_null() {
         &[][..]
      } else {
         // SAFETY: `bytes`/`len` are the bridge's borrowed buffer, valid for
         // the dispatch call.
         unsafe { slice::from_raw_parts(bytes, len) }
      };
      let action = HOOKS.apply(frame);
      let returned = match action {
         Action::Drop => ptr::null_mut(),
         Action::Pass => unsafe { (bridge.original)(data, bytes, len, out) },
         Action::Replace(ref owned) => unsafe {
            (bridge.original)(data, owned.as_ptr(), owned.len(), out)
         },
      };
      called.set(true);
      result.set(returned);
      IN_DISPATCH.set(false);
      returned
   }));
   match outcome {
      Ok(returned) => returned,
      Err(_) => {
         log::error!("events: a sink panicked, the original event was kept");
         IN_DISPATCH.set(false);
         if called.get() {
            result.get()
         } else {
            unsafe { (bridge.original)(data, bytes, len, out) }
         }
      },
   }
}

/// Routes frames containing a registered accessibility id to its callback.
/// Matching is byte-based and observation-only until frames are decoded.
pub struct AccessibilityRouter {
   rows:         RwLock<Vec<(String, Box<dyn Fn() + Send + Sync>)>>,
   drop_matched: AtomicBool,
}

impl AccessibilityRouter {
   #[must_use]
   pub const fn new() -> Self {
      Self {
         rows:         RwLock::new(Vec::new()),
         drop_matched: AtomicBool::new(false),
      }
   }

   /// Registers a callback for `id`.
   pub fn register(&self, id: impl Into<String>, handler: Box<dyn Fn() + Send + Sync>) {
      self.rows
         .write()
         .unwrap_or_else(PoisonError::into_inner)
         .push((id.into(), handler));
   }

   /// Whether a matched frame is swallowed (off until the frame schema is known).
   pub fn set_drop_matched(&self, drop: bool) {
      self.drop_matched.store(drop, Ordering::Release);
   }
}

impl Default for AccessibilityRouter {
   fn default() -> Self {
      Self::new()
   }
}

impl EventSink for AccessibilityRouter {
   fn dispatch(&self, frame: &[u8]) -> Action {
      let rows = self.rows.read().unwrap_or_else(PoisonError::into_inner);
      for (id, handler) in rows.iter() {
         if !id.is_empty()
            && frame
               .windows(id.len())
               .any(|window| window == id.as_bytes())
         {
            if catch_unwind(AssertUnwindSafe(|| handler())).is_err() {
               log::warn!("events: a row handler panicked for {id}");
            }
            if self.drop_matched.load(Ordering::Acquire) {
               return Action::Drop;
            }
         }
      }
      Action::Pass
   }
}

/// The router the settings scaffolding uses for its own rows.
pub static ROUTER: AccessibilityRouter = AccessibilityRouter::new();

#[cfg(test)]
mod tests {
   use super::*;

   struct FakeMemory(std::collections::HashMap<u64, u64>);
   impl MemoryReader for FakeMemory {
      fn word(&self, addr: u64) -> Option<u64> {
         self.0.get(&addr).copied()
      }
   }

   struct FakeMap;
   impl ImageMap for FakeMap {
      fn is_code(&self, addr: u64) -> bool {
         (0x1000..0x2000).contains(&addr)
      }

      fn pointer_slots(&self) -> Vec<(usize, u64)> {
         vec![(0x8000, 0x9000), (0x8008, 0xd000)]
      }
   }

   fn memory(host: u64) -> FakeMemory {
      let mut words = std::collections::HashMap::new();
      words.insert(0x8000, host);
      words.insert(0x8008, 0xd000);
      words.insert(host + field::GUEST, 0x9100);
      words.insert(0x9100 + field::TRAIT, 0x9200);
      words.insert(0x9200 + field::TRAIT_VTABLE, 0x9300);
      words.insert(0x9300, 0x1100); // drop
      words.insert(0x9300 + field::VTABLE_DISPATCH, 0x1200);
      FakeMemory(words)
   }

   #[test]
   fn pinned_path_finds_the_live_vtable() {
      let guest = discover(&memory(0x9000), &FakeMap, Some(0x8000)).unwrap();
      assert_eq!(guest.dispatch, 0x1200);
      assert_eq!(guest.slot, 0x9320);
      assert_eq!(guest.host_slot, 0x8000);
   }

   #[test]
   fn structural_search_ignores_non_guests() {
      let guest = discover(&memory(0x9000), &FakeMap, None).unwrap();
      assert_eq!(guest.host, 0x9000);
   }

   #[test]
   fn bogus_pinned_slot_falls_back_and_reports_failure() {
      let empty = FakeMemory(std::collections::HashMap::new());
      assert_eq!(
         discover(&empty, &FakeMap, Some(0x8000)),
         Err(DiscoveryError::PinnedInvalid)
      );
   }

   struct ReplaceOnce;
   impl EventSink for ReplaceOnce {
      fn dispatch(&self, frame: &[u8]) -> Action {
         if frame == b"a" {
            Action::Replace(b"b".to_vec())
         } else {
            Action::Pass
         }
      }
   }

   struct DropAll;
   impl EventSink for DropAll {
      fn dispatch(&self, _: &[u8]) -> Action {
         Action::Drop
      }
   }

   struct Panics;
   impl EventSink for Panics {
      fn dispatch(&self, _: &[u8]) -> Action {
         panic!("test");
      }
   }

   #[test]
   fn sinks_chain_and_can_drop() {
      let hooks = EventHooks::new();
      hooks.install(Box::new(ReplaceOnce));
      hooks.install(Box::new(Panics));
      assert_eq!(hooks.apply(b"a"), Action::Replace(b"b".to_vec()));
      hooks.install(Box::new(DropAll));
      assert!(matches!(hooks.apply(b"a"), Action::Drop));
   }

   #[test]
   fn no_sinks_is_no_work() {
      let hooks = EventHooks::new();
      assert!(!hooks.watching());
      assert!(matches!(hooks.apply(b"a"), Action::Pass));
   }

   #[test]
   fn router_matches_registered_ids() {
      let router = AccessibilityRouter::new();
      router.register("phoenix-row", Box::new(|| {}));
      assert!(matches!(router.dispatch(b"xxphoenix-rowxx"), Action::Pass));
      router.set_drop_matched(true);
      assert!(matches!(router.dispatch(b"xxphoenix-rowxx"), Action::Drop));
      assert!(matches!(router.dispatch(b"other"), Action::Pass));
   }
}
