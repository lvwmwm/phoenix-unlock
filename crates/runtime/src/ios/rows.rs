//! Native row injection at the decoded Swift op applier (`0x3496e8`, iOS arm64).
//!
//! The applier consumes a Swift `Array<Op>`: count `+0x10`, elements `+0x20`,
//! stride `0x30`, op code = byte `+0x28`. Children (code 2) carries a Swift
//! `Array<Int>` of view ids in `w1`; index 0 is the top row. See
//! `analysis/ios-ui-spec/APPLIER-DECODE.md` for the full decode.
//!
//! We find the `settings.row.logout` row, walk its parents through the
//! Children ops, and splice a fresh id into the topmost list's child array. A
//! cloned Create (code 0) for that id is appended to the same batch.
//!
//! Jailbroken only: Dobby patches the applier's code. The UUID gate keeps
//! every other build, and every non-iOS target, untouched.
//!
//! ABI risk: the real applier is called with x0=ops and a hidden x20=module;
//! it has no x1 argument. Our detour takes (ops, incoming x1) and chains with
//! the same words, relying on AAPCS64 callee-saved x19..x28 to preserve the
//! module in x20. See HANDOFF.md.

#[cfg(target_vendor = "apple")]
use std::{
   hint::spin_loop,
   mem::transmute,
   ptr::NonNull,
   sync::atomic::AtomicPtr,
};
use std::{
   cell::{
      Cell,
      RefCell,
   },
   collections::HashSet,
   ffi::c_void,
   mem::size_of,
   panic::{
      AssertUnwindSafe,
      catch_unwind,
   },
   ptr,
   sync::{
      Arc,
      Mutex,
      MutexGuard,
      OnceLock,
      PoisonError,
      atomic::{
         AtomicBool,
         AtomicU64,
         Ordering,
      },
   },
};

use phoenix_hook::Image;

#[cfg(target_vendor = "apple")]
use super::{
   events::slide_of,
   layout::{
      APPLIER,
      PINNED_UUID,
   },
};

/// Unslid storage header offsets (Swift `_ArrayStorage`).
const COUNT: usize = 0x10;
const CAP: usize = 0x08;
const DATA: usize = 0x20;
/// Op element stride and code byte, from the applier's loop.
const STRIDE: usize = 0x30;
const CODE: usize = 0x28;
/// Child `Array<Int>` header and element stride.
const ARRAY_HEADER: usize = 0x20;
const CHILD_STRIDE: usize = 8;
/// Bounds that separate an ops array from the small `x0+0x20` hook noise.
const MAX_OPS: u64 = 2000;
const MAX_DEPTH: usize = 8;

/// Stable accessibility id of the Settings logout row.
pub const MARKER: &str = "settings.row.logout";
/// Default title used until plugin/settings code supplies one.
pub const DEFAULT_TITLE: &str = "Phoenix Unlocker";
/// Sparse id range that cannot collide with host view ids (Android parity).
pub const OWN_ID_BASE: u64 = 0x5000_0000;

// ---------------------------------------------------------------------------
// Decoded views. All guest access is volatile: the arrays belong to Swift.
// ---------------------------------------------------------------------------

fn heap_like(p: *const u8) -> bool {
   let addr = p as usize;
   // Reject 0x8 / 0xe / 0x127 style scalars seen in unrelated block dispatches.
   addr >= 0x1_0000 && addr % 16 == 0
}

/// A Swift `Array<Op>` storage object.
#[derive(Clone, Copy, Debug)]
pub struct OpArray {
   base: *mut c_void,
}

impl OpArray {
   #[must_use]
   pub const fn new(base: *mut c_void) -> Self {
      Self { base }
   }

   #[must_use]
   pub fn is_null(&self) -> bool {
      self.base.is_null()
   }

   fn word(&self, at: usize) -> u64 {
      // SAFETY: `at` is a fixed header word; callers check the storage is live.
      unsafe { ptr::read_volatile(self.base.cast::<u8>().add(at).cast::<u64>()) }
   }

   #[must_use]
   pub fn count(&self) -> u64 {
      self.word(COUNT)
   }

   #[must_use]
   pub fn capacity(&self) -> u64 {
      self.word(CAP)
   }

   #[must_use]
   pub fn data(&self) -> *mut u8 {
      self.word(DATA) as *mut u8
   }

   /// Applies the validity filter from APPLIER-DECODE §7.
   #[must_use]
   pub fn is_valid(&self) -> bool {
      if !heap_like(self.base.cast::<u8>()) {
         return false;
      }
      let count = self.count();
      if !(1..=MAX_OPS).contains(&count) || self.capacity() < count {
         return false;
      }
      let data = self.data();
      heap_like(data) && self.elem(0).is_some_and(|op| op.code() <= 9)
   }

   #[must_use]
   pub fn elem(&self, index: u64) -> Option<Op> {
      if index >= self.count() {
         return None;
      }
      let data = self.data();
      if !heap_like(data) {
         return None;
      }
      let offset = usize::try_from(index).ok()?.checked_mul(STRIDE)?;
      // SAFETY: the element offset is inside the live storage.
      Some(Op { ptr: unsafe { data.add(offset) } })
   }

   /// Unused element at `count`, used to append one op.
   fn spare(&self) -> Option<Op> {
      let count = self.count();
      if count >= self.capacity() || count >= MAX_OPS {
         return None;
      }
      let data = self.data();
      if !heap_like(data) {
         return None;
      }
      let offset = usize::try_from(count).ok()?.checked_mul(STRIDE)?;
      // SAFETY: `count < capacity`, so the slot is inside the allocation.
      Some(Op { ptr: unsafe { data.add(offset) } })
   }

   /// Bumps the element count after the appended op has been written.
   fn set_count(&self, count: u64) -> bool {
      if count > self.capacity() || count > MAX_OPS {
         return false;
      }
      // SAFETY: the count word is writable guest memory.
      unsafe { ptr::write_volatile(self.base.cast::<u8>().add(COUNT).cast::<u64>(), count) };
      true
   }
}

/// One 0x30-byte op record.
#[derive(Clone, Copy, Debug)]
pub struct Op {
   ptr: *mut u8,
}

impl Op {
   #[must_use]
   pub fn code(&self) -> u8 {
      // SAFETY: byte +0x28 of a live element; the upper word bytes are garbage.
      unsafe { ptr::read_volatile(self.ptr.add(CODE)) }
   }

   #[must_use]
   pub fn word(&self, k: usize) -> u64 {
      if k >= 5 {
         return 0;
      }
      // SAFETY: words 0..4 of a live element.
      unsafe { ptr::read_volatile(self.ptr.add(k * size_of::<u64>()).cast::<u64>()) }
   }

   pub fn set_word(&self, k: usize, value: u64) -> bool {
      if k >= 5 {
         return false;
      }
      // SAFETY: words 0..4 of a live element are writable.
      unsafe { ptr::write_volatile(self.ptr.add(k * size_of::<u64>()).cast::<u64>(), value) };
      true
   }

   pub fn set_code(&self, code: u8) -> bool {
      if code > 9 {
         return false;
      }
      // SAFETY: byte +0x28 of a live element.
      unsafe { ptr::write_volatile(self.ptr.add(CODE), code) };
      true
   }

   #[must_use]
   pub fn words(&self) -> [u64; 5] {
      [self.word(0), self.word(1), self.word(2), self.word(3), self.word(4)]
   }
}

/// A Swift `Array<Int>` payload. Elements are 8-byte ids at `+0x20`.
#[derive(Clone, Copy, Debug)]
struct IntArray {
   base: *mut c_void,
}

impl IntArray {
   fn from_word(word: u64) -> Option<Self> {
      let base = word as *mut c_void;
      if !heap_like(base.cast::<u8>()) {
         return None;
      }
      let array = Self { base };
      let count = array.count();
      if !(1..=MAX_OPS).contains(&count) || array.capacity() < count {
         return None;
      }
      heap_like(array.data()).then_some(array)
   }

   fn word(&self, at: usize) -> u64 {
      // SAFETY: fixed header word of a live child array.
      unsafe { ptr::read_volatile(self.base.cast::<u8>().add(at).cast::<u64>()) }
   }

   fn count(&self) -> u64 {
      self.word(COUNT)
   }

   fn capacity(&self) -> u64 {
      self.word(CAP)
   }

   fn data(&self) -> *mut u8 {
      self.word(DATA) as *mut u8
   }

   /// Copies the ids out of guest memory before any writes happen.
   fn ids(&self) -> Vec<u64> {
      let count = self.count().min(MAX_OPS) as usize;
      let data = self.data();
      (0..count)
         .map(|index| {
            // SAFETY: `index` is below the checked count.
            unsafe { ptr::read_volatile(data.add(index * CHILD_STRIDE).cast::<u64>()) }
         })
         .collect()
   }

   /// Allocates a new array with `ids`, copying metadata from `template`.
   /// Intentionally leaked: Swift may retain it after the applier returns.
   fn alloc(ids: &[u64], template: Self) -> Option<Self> {
      let bytes = ARRAY_HEADER.checked_add(ids.len().checked_mul(CHILD_STRIDE)?)?;
      // SAFETY: malloc takes a byte count; the null check guards every write.
      let base = unsafe { libc::malloc(bytes) }.cast::<u8>();
      if base.is_null() {
         return None;
      }
      let count = ids.len() as u64;
      unsafe {
         let meta = ptr::read_volatile(template.base.cast::<u8>().cast::<u64>());
         ptr::write_volatile(base.cast::<u64>(), meta);
         ptr::write_volatile(base.add(CAP).cast::<u64>(), count);
         ptr::write_volatile(base.add(COUNT).cast::<u64>(), count);
         ptr::write_volatile(base.add(0x18).cast::<u64>(), count);
         for (index, id) in ids.iter().enumerate() {
            let at = base.add(ARRAY_HEADER + index * CHILD_STRIDE).cast::<u64>();
            ptr::write_volatile(at, *id);
         }
      }
      Some(Self { base: base.cast() })
   }
}

// ---------------------------------------------------------------------------
// Anchor discovery (host-testable).
// ---------------------------------------------------------------------------

fn printable(byte: u8) -> bool {
   byte == b' ' || byte.is_ascii_graphic()
}

/// Inline ASCII run, skipping a Swift small-string header byte.
fn ascii_text(word: u64) -> Option<String> {
   let bytes = word.to_le_bytes();
   let start = usize::from(!printable(bytes[0]));
   let len = bytes[start..].iter().take_while(|&&byte| printable(byte)).count();
   if len < 4 {
      return None;
   }
   std::str::from_utf8(&bytes[start..start + len]).ok().map(str::to_owned)
}

/// UTF-16LE code units packed into one word (the live text shape).
fn utf16_text(word: u64) -> Option<String> {
   let mut text = String::new();
   for pair in word.to_le_bytes().chunks_exact(2) {
      let unit = u16::from_le_bytes([pair[0], pair[1]]);
      if !(0x20..=0x7e).contains(&unit) {
         return None;
      }
      text.push(char::from(unit as u8));
   }
   (text.len() >= 4).then_some(text)
}

fn word_text(word: u64) -> Option<String> {
   match (ascii_text(word), utf16_text(word)) {
      (Some(ascii), Some(utf16)) => Some(if ascii.len() >= utf16.len() { ascii } else { utf16 }),
      (ascii, utf16) => ascii.or(utf16),
   }
}

/// All printable runs of one op, in word order. The marker spans 3 words.
fn op_text(words: &[u64; 5]) -> String {
   let mut out = String::new();
   for &word in words {
      if let Some(text) = word_text(word) {
         out.push_str(&text);
      }
   }
   out
}

fn captured() -> Option<[u64; 5]> {
   let slot = CAPTURED
      .get_or_init(|| Mutex::new(None))
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
   (*slot).unwrap_or(None)
}

fn remember_create(words: [u64; 5]) {
   let mut slot = CAPTURED
      .get_or_init(|| Mutex::new(None))
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
   if slot.is_none() {
      *slot = Some(words);
   }
}

struct Target {
   index: u64,
   list_id: u64,
   children: Op,
   create: [u64; 5],
}

/// Finds the topmost list Children op whose ids contain an ancestor of the
/// logout row, mirroring Android's `find_screen` parent walk.
fn find_target(ops: &OpArray) -> Option<Target> {
   let count = ops.count().min(MAX_OPS);
   let mut anchors = Vec::new();
   let mut parent_of = HashSet::new();
   let mut first_create = None;

   for index in 0..count {
      let op = ops.elem(index)?;
      let words = op.words();
      if op_text(&words).contains(MARKER) {
         anchors.push(words[0]);
         if op.code() == 0 {
            first_create = Some(words);
         }
      }
      if op.code() == 0 && first_create.is_none() {
         let kind = word_text(words[1]).or_else(|| word_text(words[2]));
         if kind.is_some() {
            first_create = Some(words);
         }
      }
      if op.code() == 2
         && let Some(array) = IntArray::from_word(words[1])
      {
         for child in array.ids() {
            parent_of.insert((child, words[0]));
         }
      }
   }

   if let Some(words) = first_create {
      remember_create(words);
   }
   let create = first_create.or_else(captured)?;
   let anchor = *anchors.first()?;

   // row -> group -> list; stop at the first repeated id.
   let mut chain = vec![anchor];
   for _ in 0..MAX_DEPTH {
      let last = *chain.last()?;
      let Some(parent) = parent_of
         .iter()
         .find_map(|&(child, parent)| (child == last).then_some(parent))
      else {
         break;
      };
      if chain.contains(&parent) {
         break;
      }
      chain.push(parent);
   }

   for index in 0..count {
      let children = ops.elem(index)?;
      if children.code() != 2 {
         continue;
      }
      let list_id = children.word(0);
      let Some(at) = chain.iter().position(|&id| id == list_id) else {
         continue;
      };
      // Prefer the topmost ancestor: that is the list, not the row's group.
      if at == 0 || at + 1 != chain.len() {
         continue;
      }
      // The child below `list_id` must be on the walk from the logout row.
      let Some(array) = IntArray::from_word(children.word(1)) else {
         continue;
      };
      if !array.ids().contains(&chain[at - 1]) {
         continue;
      }
      return Some(Target { index, list_id, children, create });
   }
   None
}

fn allocate_id() -> u64 {
   NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn fresh_id(ops: &OpArray) -> u64 {
   for _ in 0..16 {
      let id = allocate_id();
      let taken = (0..ops.count().min(MAX_OPS)).any(|index| {
         ops.elem(index).is_some_and(|op| op.words().contains(&id))
      });
      if !taken {
         return id;
      }
   }
   OWN_ID_BASE
}

// ---------------------------------------------------------------------------
// Injection.
// ---------------------------------------------------------------------------

static NEXT_ID: AtomicU64 = AtomicU64::new(OWN_ID_BASE);
static ENABLED: AtomicBool = AtomicBool::new(true);
static LOGGED: AtomicBool = AtomicBool::new(false);
static CAPTURED: OnceLock<Mutex<Option<[u64; 5]>>> = OnceLock::new();

thread_local! {
   /// List ids already patched in the current frame.
   static PATCHED: RefCell<HashSet<u64>> = RefCell::new(HashSet::new());
   static IN_APPLY: Cell<bool> = Cell::new(false);
}

/// Marks a new applier frame; call before [`inject_top_row`] in the detour.
pub fn begin_frame() {
   PATCHED.with(|patched| patched.borrow_mut().clear());
}

fn guard<R>(run: impl FnOnce() -> R) -> Option<R> {
   catch_unwind(AssertUnwindSafe(run)).ok()
}

/// Injects one row at the top of the Settings list in `ops`.
///
/// Returns true when a Children op was rewritten and a Create appended. The
/// detour calls this before chaining to the original applier.
#[must_use]
pub fn inject_top_row(ops: *mut c_void) -> bool {
   inject_inner(ops, ENABLED.load(Ordering::Acquire))
}

fn inject_inner(ops: *mut c_void, enabled: bool) -> bool {
   if !enabled {
      return false;
   }
   let array = OpArray::new(ops);
   guard(|| -> Option<bool> {
      if !array.is_valid() {
         return Some(false);
      }
      let Some(target) = find_target(&array) else {
         return Some(false);
      };
      let duplicate = PATCHED.with(|patched| !patched.borrow_mut().insert(target.list_id));
      if duplicate {
         return Some(false);
      }
      // Check for room before the first write so a full batch stays intact.
      let Some(spare) = array.spare() else {
         return Some(false);
      };
      let fresh = fresh_id(&array);
      let Some(old) = IntArray::from_word(target.children.word(1)) else {
         return Some(false);
      };
      let mut ids = Vec::with_capacity(old.ids().len() + 1);
      ids.push(fresh);
      ids.extend(old.ids());
      let Some(new_ids) = IntArray::alloc(&ids, old) else {
         return Some(false);
      };

      target.children.set_word(1, new_ids.base as u64);
      let mut words = target.create;
      words[0] = fresh;
      for (k, word) in words.iter().copied().enumerate() {
         spare.set_word(k, word);
      }
      spare.set_code(0);
      array.set_count(array.count() + 1);

      if LOGGED
         .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
         .is_ok()
      {
         log::info!(
            "rows: injected id {fresh:#x} at the top of list {:#x} (op {}, {} ids)",
            target.list_id,
            target.index,
            ids.len()
         );
      }
      Some(true)
   })
   .flatten()
   .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Row title / action (taps are not routed yet).
// ---------------------------------------------------------------------------

pub struct RowHook {
   pub title:  String,
   pub action: Arc<dyn Fn() + Send + Sync>,
}

static HOOKS: OnceLock<Mutex<Vec<RowHook>>> = OnceLock::new();

fn hooks() -> MutexGuard<'static, Vec<RowHook>> {
   HOOKS
      .get_or_init(|| Mutex::new(Vec::new()))
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
}

/// Supplies the title and action of the injected row. The action is retained
/// but cannot fire yet: no reverse view-event hook has been found on iOS.
pub fn add_row_hook(title: impl Into<String>, action: Box<dyn Fn() + Send + Sync>) {
   hooks().push(RowHook {
      title:  title.into(),
      action: Arc::from(action),
   });
   ENABLED.store(true, Ordering::Release);
   ensure_installed();
}

/// First registered title, or the default.
#[must_use]
pub fn row_title() -> String {
   hooks().first().map_or_else(|| DEFAULT_TITLE.to_owned(), |hook| hook.title.clone())
}

/// Disables injection; the detour then chains straight to the applier.
pub fn set_enabled(enabled: bool) {
   ENABLED.store(enabled, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Live process plumbing (Apple only; host tests use the views above).
// ---------------------------------------------------------------------------

#[cfg(target_vendor = "apple")]
struct Chain {
   original: AtomicPtr<c_void>,
}

#[cfg(target_vendor = "apple")]
static CHAIN: AtomicPtr<Chain> = AtomicPtr::new(ptr::null_mut());
#[cfg(target_vendor = "apple")]
static INSTALLED: AtomicBool = AtomicBool::new(false);
#[cfg(target_vendor = "apple")]
static INSTALLING: AtomicBool = AtomicBool::new(false);
#[cfg(target_vendor = "apple")]
static PREPARED: OnceLock<&'static Image<'static>> = OnceLock::new();
#[cfg(target_vendor = "apple")]
static KEEPALIVE: OnceLock<phoenix_hook::Inline> = OnceLock::new();

/// Installs for the pinned build after `events::prepare(image)`.
pub fn start(image: &'static Image<'static>) {
   #[cfg(target_vendor = "apple")]
   {
      let uuid = image.build_id.map(|id| id.to_string());
      if uuid.as_deref() != Some(PINNED_UUID) {
         log::warn!(
            "rows: build {} does not match {PINNED_UUID}; the inline hook stays uninstalled",
            uuid.as_deref().unwrap_or("unknown")
         );
         return;
      }
      let _ = PREPARED.set(image);
      ensure_installed();
   }
   #[cfg(not(target_vendor = "apple"))]
   let _ = image;
}

#[cfg(target_vendor = "apple")]
#[must_use]
pub fn installed() -> bool {
   INSTALLED.load(Ordering::Acquire)
}

#[cfg(not(target_vendor = "apple"))]
#[must_use]
pub fn installed() -> bool {
   false
}

#[cfg(target_vendor = "apple")]
fn ensure_installed() {
   use phoenix_hook::Hook;

   if INSTALLED.load(Ordering::Acquire) || INSTALLING.swap(true, Ordering::AcqRel) {
      return;
   }
   let outcome = (|| -> Option<usize> {
      let image = *PREPARED.get()?;
      let slide = slide_of(image)?;
      let target = usize::try_from(slide).ok()?.checked_add(APPLIER as usize)?;
      let chain = Box::into_raw(Box::new(Chain {
         original: AtomicPtr::new(ptr::null_mut()),
      }));
      if CHAIN
         .compare_exchange(ptr::null_mut(), chain, Ordering::AcqRel, Ordering::Acquire)
         .is_err()
      {
         // SAFETY: `chain` was just allocated and never published.
         unsafe { drop(Box::from_raw(chain)) };
         return None;
      }
      // SAFETY: `target` is the first instruction of the op applier. The
      // detour's ABI risk is documented at the top of this module; `pw` only
      // names an address, never derefs it.
      let pw = ptr::without_provenance_mut::<c_void>;
      let hooked = unsafe {
         phoenix_hook::Inline::attach(
            NonNull::new(pw(target))?,
            NonNull::new(pw(trampoline as usize))?,
         )
      };
      let hook = match hooked {
         Ok(hook) => hook,
         Err(err) => {
            CHAIN.store(ptr::null_mut(), Ordering::Release);
            // SAFETY: the chain is unpublished again and still ours.
            unsafe { drop(Box::from_raw(chain)) };
            log::error!("rows: could not hook {target:#x}: {err}");
            return None;
         },
      };
      // The patch is live: publish Dobby's trampoline before any invocation.
      // SAFETY: `chain` was published above and is never freed.
      unsafe { (*chain).original.store(hook.original().as_ptr(), Ordering::Release) };
      let _ = KEEPALIVE.set(hook);
      INSTALLED.store(true, Ordering::Release);
      Some(target)
   })();
   if let Some(target) = outcome {
      log::info!("rows: hooked Swift op applier at {target:#x}");
   }
   INSTALLING.store(false, Ordering::Release);
}

#[cfg(not(target_vendor = "apple"))]
fn ensure_installed() {
   log::debug!("rows: inline installation is iOS-only");
}

#[cfg(target_vendor = "apple")]
type ApplierFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

#[cfg(target_vendor = "apple")]
unsafe extern "C" fn trampoline(ops: *mut c_void, module: *mut c_void) {
   let Some(chain) = (unsafe { CHAIN.load(Ordering::Acquire).as_ref() }) else {
      return;
   };
   let original = loop {
      let pointer = chain.original.load(Ordering::Acquire);
      if !pointer.is_null() {
         break unsafe { transmute::<*mut c_void, ApplierFn>(pointer) };
      }
      spin_loop();
   };
   // x20 (module) is preserved by AAPCS64; the second argument is only
   // forwarded to keep every incoming register word the same.
   if IN_APPLY.get() || !ENABLED.load(Ordering::Acquire) {
      unsafe { original(ops, module) };
      return;
   }
   let chained = Cell::new(false);
   let result = catch_unwind(AssertUnwindSafe(|| {
      IN_APPLY.set(true);
      begin_frame();
      let _ = inject_top_row(ops);
      chained.set(true);
      unsafe { original(ops, module) };
      IN_APPLY.set(false);
   }));
   if result.is_err() {
      log::error!("rows: an injection panicked, the original applier still ran");
      IN_APPLY.set(false);
      if !chained.get() {
         unsafe { original(ops, module) };
      }
   }
}

// ---------------------------------------------------------------------------
// Host unit tests: synthetic buffers, no device and no inline hook.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
   use super::*;

   /// Count, capacity, data pointer and `count` 0x30-byte elements.
   struct FakeOps {
      header: Vec<u64>,
      elems:  Vec<u64>,
   }

   impl FakeOps {
      fn new(count: u64, cap: u64) -> Self {
         let mut elems = vec![0u64; count as usize * STRIDE / 8];
         for (index, word) in elems.iter_mut().enumerate() {
            *word = 0x1000 + index as u64; // unique, non-marker words
         }
         Self {
            header: vec![0, cap, count, cap, 0],
            elems,
         }
      }

      fn set(&mut self, index: usize, words: [u64; 5], code: u8) {
         let at = index * STRIDE / 8;
         self.elems[at..at + 5].copy_from_slice(&words);
         self.elems[at + CODE / 8] = code.into();
      }

      fn ptr(&mut self) -> *mut c_void {
         // The header's data word must point at the (heap) element buffer.
         self.header[DATA / 8] = self.elems.as_mut_ptr() as u64;
         self.header.as_mut_ptr().cast()
      }
   }

   fn int_array(ids: &[u64]) -> (*mut c_void, IntArray) {
      let bytes = ARRAY_HEADER + ids.len() * CHILD_STRIDE;
      // SAFETY: a fresh allocation of `bytes` for the test array.
      let base = unsafe { libc::malloc(bytes) }.cast::<u8>();
      assert!(!base.is_null());
      unsafe {
         ptr::write_volatile(base.cast::<u64>(), 0xaa); // metadata
         ptr::write_volatile(base.add(CAP).cast::<u64>(), ids.len() as u64);
         ptr::write_volatile(base.add(COUNT).cast::<u64>(), ids.len() as u64);
         ptr::write_volatile(base.add(0x18).cast::<u64>(), ids.len() as u64);
         for (index, id) in ids.iter().enumerate() {
            ptr::write_volatile(
               base.add(ARRAY_HEADER + index * CHILD_STRIDE).cast::<u64>(),
               *id,
            );
         }
      }
      (base.cast(), IntArray::from_word(base as u64).expect("valid array"))
   }

   fn settings_ops() -> FakeOps {
      let mut ops = FakeOps::new(4, 8);
      let mut row = [0u64; 5];
      row[0] = 0x100;
      row[1] = u64::from_le_bytes(*b"settings");
      row[2] = u64::from_le_bytes(*b".row.log");
      row[3] = u64::from_le_bytes(*b"out \0\0\0\0");
      ops.set(0, row, 0); // the logout row Create

      let (group_ids, _) = int_array(&[0x100]);
      let mut group = [0u64; 5];
      group[0] = 0x200;
      group[1] = group_ids as u64;
      ops.set(1, group, 2); // row -> group

      let (list_ids, _) = int_array(&[0x200, 0x222]);
      let mut list = [0u64; 5];
      list[0] = 0x300;
      list[1] = list_ids as u64;
      ops.set(2, list, 2); // group -> list
      ops
   }

   #[test]
   fn parses_header_stride_and_code() {
      let mut ops = FakeOps::new(3, 7);
      ops.set(2, [1, 2, 3, 4, 5], 2);
      let view = OpArray::new(ops.ptr());
      assert!(view.is_valid());
      assert_eq!(view.count(), 3);
      assert_eq!(view.capacity(), 7);
      let op = view.elem(2).expect("element 2");
      assert_eq!(op.code(), 2);
      assert_eq!(op.words(), [1, 2, 3, 4, 5]);
      assert_eq!(op.word(3), 4);
      assert!(!op.set_word(5, 9));
      assert_eq!(op.word(5), 0);
      assert!(view.elem(3).is_none());
   }

   #[test]
   fn validity_filter_rejects_hook_noise() {
      let mut ops = FakeOps::new(1, 1);
      let valid = OpArray::new(ops.ptr());
      assert!(valid.is_valid());

      assert!(!OpArray::new(ptr::null_mut()).is_valid());
      let mut empty = FakeOps::new(0, 4);
      assert!(!OpArray::new(empty.ptr()).is_valid());
      let mut huge = FakeOps::new(MAX_OPS + 1, MAX_OPS + 2);
      assert!(!OpArray::new(huge.ptr()).is_valid());
      let mut over = FakeOps::new(4, 2);
      assert!(!OpArray::new(over.ptr()).is_valid());

      let mut unaligned = FakeOps::new(1, 1);
      let header = unaligned.ptr().cast::<u64>();
      unsafe { ptr::write_volatile(header.add(DATA / 8), 0x8) };
      assert!(!OpArray::new(header.cast()).is_valid());

      let mut bad_tag = FakeOps::new(1, 1);
      bad_tag.set(0, [0; 5], 0x40);
      assert!(!OpArray::new(bad_tag.ptr()).is_valid());
   }

   #[test]
   fn child_ids_are_copied_and_prepended() {
      let (base, array) = int_array(&[11, 22, 33]);
      assert_eq!(array.ids(), vec![11, 22, 33]);
      let mut ids = vec![allocate_id()];
      ids.extend(array.ids());
      assert_eq!(ids.len(), 4);
      assert!(ids[0] >= OWN_ID_BASE);
      assert_eq!(&ids[1..], &[11, 22, 33]);
      // SAFETY: `base` was malloc'd in this test and freed here.
      unsafe { libc::free(base) };
   }

   #[test]
   fn alloc_int_array_keeps_metadata_and_prepended_order() {
      let (old_base, old) = int_array(&[7, 8]);
      let fresh = OWN_ID_BASE + 99;
      let new = IntArray::alloc(&[fresh, 7, 8], old).expect("allocation");
      assert_eq!(new.count(), 3);
      assert_eq!(new.ids(), vec![fresh, 7, 8]);
      assert_eq!(new.word(0), old.word(0));
      // SAFETY: both buffers were malloc'd in this test.
      unsafe {
         libc::free(old_base);
         libc::free(new.base);
      }
   }

   #[test]
   fn own_ids_are_sparse_and_increasing() {
      let first = allocate_id();
      let second = allocate_id();
      assert!(first >= OWN_ID_BASE);
      assert!(second > first);
   }

   #[test]
   fn injects_once_at_the_top_of_the_list() {
      let mut ops = settings_ops();
      let base = ops.ptr();
      let view = OpArray::new(base);
      let row_words = view.elem(0).unwrap().words();
      begin_frame();
      assert!(inject_top_row(base));

      assert_eq!(view.count(), 5);
      let list = view.elem(2).expect("list Children");
      assert_eq!(list.code(), 2);
      let ids = IntArray::from_word(list.word(1)).expect("new child array").ids();
      assert_eq!(ids.len(), 3);
      assert!(ids[0] >= OWN_ID_BASE);
      assert_eq!(&ids[1..], &[0x200, 0x222]);

      let appended = view.elem(4).expect("appended Create");
      assert_eq!(appended.code(), 0);
      assert_eq!(appended.word(0), ids[0]);
      assert_eq!(&appended.words()[1..], &row_words[1..]);

      // Same frame: the list is already patched, so nothing changes.
      assert!(!inject_top_row(base));
      assert_eq!(view.count(), 5);
      assert_eq!(IntArray::from_word(list.word(1)).unwrap().ids(), ids);
   }

   #[test]
   fn no_marker_means_no_injection() {
      let mut ops = FakeOps::new(1, 4);
      let (ids, _) = int_array(&[0x111]);
      let mut children = [0u64; 5];
      children[1] = ids as u64;
      ops.set(0, children, 2);
      let base = ops.ptr();
      begin_frame();
      assert!(!inject_top_row(base));
      assert_eq!(OpArray::new(base).count(), 1);
   }

   #[test]
   fn full_batch_is_left_untouched() {
      let mut ops = settings_ops();
      ops.header[CAP / 8] = 4; // count == capacity: no spare element
      let base = ops.ptr();
      let before = OpArray::new(base).elem(2).unwrap().word(1);
      begin_frame();
      assert!(!inject_top_row(base));
      assert_eq!(OpArray::new(base).elem(2).unwrap().word(1), before);
      assert_eq!(OpArray::new(base).count(), 4);
   }

   #[test]
   fn disabled_hook_is_a_no_op() {
      let mut ops = settings_ops();
      let base = ops.ptr();
      begin_frame();
      assert!(!inject_inner(base, false));
      assert_eq!(OpArray::new(base).count(), 4);
   }

   #[test]
   fn injection_survives_a_panic() {
      assert!(guard(|| -> () { panic!("test") }).is_none());
      assert_eq!(guard(|| 7), Some(7));
      // A malformed array returns false instead of unwinding.
      begin_frame();
      assert!(!inject_top_row(ptr::without_provenance_mut(0x8)));
   }

   #[test]
   fn row_hook_defaults_to_phoenix_unlocker() {
      assert_eq!(row_title(), DEFAULT_TITLE);
      add_row_hook("Custom", Box::new(|| {}));
      assert_eq!(row_title(), "Custom");
   }
}
