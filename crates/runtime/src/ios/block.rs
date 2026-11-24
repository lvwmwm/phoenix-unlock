//! Inline hook on the `applyOps` `CATransaction` block invoke (iOS, arm64).
//!
//! `applyOps(0x34926c)` builds a stack Block whose invoke function is
//! [`APPLY_OPS_BLOCK`](super::layout::APPLY_OPS_BLOCK). Live calls carry the
//! rendered UI strings directly in words 6..16 of the Block context as Swift
//! inline small strings. The detour runs before the original invoke, so a hook
//! can overwrite one of those strings in place without changing its length.
//!
//! Jailbroken only: Dobby patches the invoke function's code at runtime. The
//! UUID gate keeps every other build, and every non-iOS target, untouched.

#[cfg(target_vendor = "apple")]
use std::{
   ptr::NonNull,
   sync::{
      OnceLock,
      atomic::AtomicPtr,
   },
};
use std::{
   cell::Cell,
   ffi::c_void,
   panic::{
      AssertUnwindSafe,
      catch_unwind,
   },
   ptr,
   sync::{
      PoisonError,
      RwLock,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
};

use phoenix_hook::Image;

#[cfg(target_vendor = "apple")]
use super::{
   events::slide_of,
   layout::{
      APPLY_OPS_BLOCK,
      PINNED_UUID,
   },
};

#[cfg(target_vendor = "apple")]
type InvokeFn = unsafe extern "C" fn(*mut c_void);

/// First and last word of the captured-var area that holds inline strings.
pub const TEXT_WORD_FIRST: usize = 6;
pub const TEXT_WORD_LAST: usize = 16;
/// Shortest printable run treated as text; tagged pointers fail this test.
const MIN_TEXT: usize = 4;

// ---------------------------------------------------------------------------
// Text inspection and in-place overwrite (host-testable).
// ---------------------------------------------------------------------------

fn printable(byte: u8) -> bool {
   byte == b' ' || byte.is_ascii_graphic()
}

fn run(bytes: &[u8]) -> usize {
   bytes.iter().take_while(|&&byte| printable(byte)).count()
}

/// Byte range of one inline string: a printable run from byte 0, or (when
/// word 0 is a Swift header) a run starting at byte 1.
fn word_text(word: u64) -> Option<(usize, usize)> {
   let bytes = word.to_le_bytes();
   let full = run(&bytes);
   if full >= MIN_TEXT {
      return Some((0, full));
   }
   let tail = run(&bytes[1..]);
   if tail >= MIN_TEXT {
      return Some((1, tail));
   }
   None
}

fn word_ptr(block: *mut c_void, index: usize) -> *mut u64 {
   unsafe { block.cast::<u64>().add(index) }
}

/// Decodes the inline strings captured in words [`TEXT_WORD_FIRST`..
/// [`TEXT_WORD_LAST`]). Tagged pointers and partial words are skipped.
///
/// # Safety
///
/// `block` must be a live block context passed to the invoke, or a test
/// buffer with at least [`TEXT_WORD_LAST`] words.
#[must_use]
pub unsafe fn texts(block: *mut c_void) -> Vec<(usize, String)> {
   (TEXT_WORD_FIRST..TEXT_WORD_LAST)
      .filter_map(|index| {
         // SAFETY: forwarded from the caller.
         let word = unsafe { ptr::read_volatile(word_ptr(block, index)) };
         let (start, len) = word_text(word)?;
         let bytes = word.to_le_bytes();
         let text = std::str::from_utf8(&bytes[start..start + len])
            .unwrap_or_default()
            .to_owned();
         Some((index, text))
      })
      .collect()
}

/// Overwrites one decoded inline string. The byte width is unchanged: any
/// unused bytes of the run become spaces, and a Swift header byte is kept.
///
/// Returns false for tagged/non-text words, out-of-range indexes, non-ASCII
/// or overlong text. Nothing is written in that case.
///
/// # Safety
///
/// `block` must be a live block context passed to the invoke, or a test
/// buffer with at least [`TEXT_WORD_LAST`] words.
pub unsafe fn replace_ascii(block: *mut c_void, index: usize, text: &str) -> bool {
   if !(TEXT_WORD_FIRST..TEXT_WORD_LAST).contains(&index)
      || text.is_empty()
      || text.len() > 8
      || !text.bytes().all(printable)
   {
      return false;
   }
   let slot = word_ptr(block, index);
   // SAFETY: forwarded from the caller.
   let word = unsafe { ptr::read_volatile(slot) };
   let Some((start, len)) = word_text(word) else {
      return false;
   };
   if text.len() > len {
      return false;
   }
   let mut bytes = word.to_le_bytes();
   bytes[start..start + len].fill(b' ');
   bytes[start..start + text.len()].copy_from_slice(text.as_bytes());
   // SAFETY: a block's captured words are pointer-aligned and writable on
   // jailbroken iOS; `slot` came from a checked index.
   unsafe { ptr::write_volatile(slot, u64::from_le_bytes(bytes)) };
   true
}

// ---------------------------------------------------------------------------
// Sinks.
// ---------------------------------------------------------------------------

/// Receives the strings decoded from one block invoke. Use [`replace_ascii`]
/// on `block` to overwrite a word in place.
pub trait TextHook: Send + Sync {
   fn texts(&self, block: *mut c_void, texts: &mut Vec<(usize, String)>);
}

impl<F> TextHook for F
where
   F: Fn(*mut c_void, &mut Vec<(usize, String)>) + Send + Sync,
{
   fn texts(&self, block: *mut c_void, texts: &mut Vec<(usize, String)>) {
      self(block, texts);
   }
}

pub struct BlockHooks {
   hooks:    RwLock<Vec<Box<dyn Fn(*mut c_void) + Send + Sync>>>,
   watching: AtomicBool,
}

impl BlockHooks {
   #[must_use]
   pub const fn new() -> Self {
      Self {
         hooks:    RwLock::new(Vec::new()),
         watching: AtomicBool::new(false),
      }
   }

   pub fn install(&self, hook: Box<dyn Fn(*mut c_void) + Send + Sync>) {
      self.hooks
         .write()
         .unwrap_or_else(PoisonError::into_inner)
         .push(hook);
      self.watching.store(true, Ordering::Release);
   }

   #[must_use]
   pub fn watching(&self) -> bool {
      self.watching.load(Ordering::Acquire)
   }

   /// Runs hooks in install order, catching panics.
   pub fn apply(&self, block: *mut c_void) {
      if !self.watching() {
         return;
      }
      let hooks = self
         .hooks
         .read()
         .unwrap_or_else(PoisonError::into_inner);
      for hook in hooks.iter() {
         if catch_unwind(AssertUnwindSafe(|| hook(block))).is_err() {
            log::error!("block: a hook panicked, the original invoke still ran");
         }
      }
   }
}

impl Default for BlockHooks {
   fn default() -> Self {
      Self::new()
   }
}

pub static HOOKS: BlockHooks = BlockHooks::new();

/// Adds a raw block-context hook, installing the inline hook on first use.
pub fn add_hook(hook: Box<dyn Fn(*mut c_void) + Send + Sync>) {
   HOOKS.install(hook);
   ensure_installed();
}

/// Adds a text hook. It sees the decoded words and can overwrite them through
/// [`replace_ascii`] on the live block pointer.
pub fn add_text_hook(hook: Box<dyn TextHook>) {
   add_hook(Box::new(move |block| {
      // SAFETY: `block` is the context our trampoline was called with.
      let mut decoded = unsafe { texts(block) };
      hook.texts(block, &mut decoded);
   }));
}

// ---------------------------------------------------------------------------
// Live process plumbing (Apple only; host tests use the helpers above).
// ---------------------------------------------------------------------------

#[cfg(target_vendor = "apple")]
struct Chain {
   /// Dobby's trampoline, stored before the patch goes in so the detour can
   /// always chain to the original body.
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
            "block: build {} does not match {PINNED_UUID}; the inline hook stays uninstalled",
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
pub fn installed() -> bool {
   INSTALLED.load(Ordering::Acquire)
}

#[cfg(not(target_vendor = "apple"))]
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
      let target = usize::try_from(slide).ok()?.checked_add(APPLY_OPS_BLOCK)?;
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
      // SAFETY: `target` is the first instruction of the block invoke; the
      // detour has the same ABI. `pw` only names an address, never derefs it.
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
            log::error!("block: could not hook {target:#x}: {err}");
            return None;
         },
      };
      // The patch is live now: publish Dobby's trampoline immediately. The
      // detour spins until this store lands rather than skipping the call.
      // SAFETY: `chain` was published above and is never freed.
      unsafe { (*chain).original.store(hook.original().as_ptr(), Ordering::Release) };
      let _ = KEEPALIVE.set(hook);
      INSTALLED.store(true, Ordering::Release);
      Some(target)
   })();
   if let Some(target) = outcome {
      log::info!("block: hooked applyOps block invoke at {target:#x}");
   }
   INSTALLING.store(false, Ordering::Release);
}

#[cfg(not(target_vendor = "apple"))]
fn ensure_installed() {
   log::debug!("block: inline installation is iOS-only");
}

#[cfg(target_vendor = "apple")]
thread_local! {
   static IN_INVOKE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(target_vendor = "apple")]
unsafe extern "C" fn trampoline(block: *mut c_void) {
   let Some(chain) = (unsafe { CHAIN.load(Ordering::Acquire).as_ref() }) else {
      return;
   };
   let original = loop {
      let pointer = chain.original.load(Ordering::Acquire);
      if !pointer.is_null() {
         break unsafe { std::mem::transmute::<*mut c_void, InvokeFn>(pointer) };
      }
      std::hint::spin_loop();
   };
   // A hook feeding the app through this same block must not see itself.
   if IN_INVOKE.get() {
      unsafe { original(block) };
      return;
   }
   let chained = Cell::new(false);
   let result = catch_unwind(AssertUnwindSafe(|| {
      IN_INVOKE.set(true);
      HOOKS.apply(block);
      chained.set(true);
      unsafe { original(block) };
      IN_INVOKE.set(false);
   }));
   if result.is_err() {
      log::error!("block: a hook panicked, the original invoke was kept");
      IN_INVOKE.set(false);
      if !chained.get() {
         unsafe { original(block) };
      }
   }
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::sync::atomic::AtomicUsize;

   fn words() -> [u64; TEXT_WORD_LAST] {
      [0; TEXT_WORD_LAST]
   }

   fn ptr(words: &mut [u64; TEXT_WORD_LAST]) -> *mut c_void {
      words.as_mut_ptr().cast()
   }

   #[test]
   fn offset_is_the_pinned_apply_ops_block() {
      assert_eq!(super::super::layout::APPLY_OPS_BLOCK, 0x0015_9618);
   }

   #[test]
   fn decodes_inline_strings_and_skips_tagged_words() {
      let mut data = words();
      data[6] = u64::from_le_bytes(*b"abcdefgh");
      data[7] = 0x21a1_f117_b0c9; // tagged pointer: no printable run
      data[8] = u64::from_le_bytes([0x15, b'C', b'a', b'l', b'l', b' ', b'D', b'e']);
      data[9] = u64::from_le_bytes(*b"n Type\0\0");
      assert_eq!(
         unsafe { texts(ptr(&mut data)) },
         vec![
            (6, "abcdefgh".to_owned()),
            (8, "Call De".to_owned()),
            (9, "n Type".to_owned()),
         ]
      );
   }

   #[test]
   fn replace_keeps_the_swift_header_and_other_words() {
      let mut data = words();
      data[6] = u64::from_le_bytes([0x15, b'L', b'o', b'g', b' ', b'O', b'u', b't']);
      data[7] = u64::from_le_bytes(*b"keepme!!");
      assert!(unsafe { replace_ascii(ptr(&mut data), 6, "Unlock!") });
      let bytes = data[6].to_le_bytes();
      assert_eq!(bytes[0], 0x15);
      assert_eq!(&bytes[1..], b"Unlock!");
      assert_eq!(data[7], u64::from_le_bytes(*b"keepme!!"));
   }

   #[test]
   fn replace_pads_a_shorter_string_without_changing_width() {
      let mut data = words();
      data[6] = u64::from_le_bytes(*b"abcdefgh");
      assert!(unsafe { replace_ascii(ptr(&mut data), 6, "hi") });
      assert_eq!(data[6], u64::from_le_bytes(*b"hi      "));
   }

   #[test]
   fn tagged_words_and_oversize_text_are_not_written() {
      let mut data = words();
      data[6] = 0x6195_1ba5_b960; // tagged pointer
      data[7] = u64::from_le_bytes(*b"abcdefgh");
      let block = ptr(&mut data);
      assert!(!unsafe { replace_ascii(block, 6, "hacked!") });
      assert!(!unsafe { replace_ascii(block, 7, "123456789") });
      assert!(!unsafe { replace_ascii(block, 7, "non ascii\u{7f}") });
      assert_eq!(data[6], 0x6195_1ba5_b960);
      assert_eq!(data[7], u64::from_le_bytes(*b"abcdefgh"));
   }

   #[test]
   fn partial_words_and_bad_indexes_are_safe() {
      let mut data = words();
      data[6] = u64::from_le_bytes([b'a', b'b', 0, 0, 0, 0, 0, 0]);
      let block = ptr(&mut data);
      assert!(unsafe { texts(block) }.is_empty());
      assert!(!unsafe { replace_ascii(block, 6, "xx") });
      assert!(!unsafe { replace_ascii(block, TEXT_WORD_FIRST - 1, "xx") });
      assert!(!unsafe { replace_ascii(block, TEXT_WORD_LAST, "xx") });
   }

   #[test]
   fn hooks_chain_and_survive_a_panic() {
      let hooks = BlockHooks::new();
      let seen = std::sync::Arc::new(AtomicUsize::new(0));
      let first = seen.clone();
      hooks.install(Box::new(move |_| {
         first.fetch_add(1, Ordering::Relaxed);
      }));
      hooks.install(Box::new(|_| panic!("test")));
      let last = seen.clone();
      hooks.install(Box::new(move |_| {
         last.fetch_add(10, Ordering::Relaxed);
      }));
      hooks.apply(ptr::null_mut());
      assert_eq!(seen.load(Ordering::Relaxed), 11);
   }

   #[test]
   fn no_hooks_is_no_work() {
      let hooks = BlockHooks::new();
      assert!(!hooks.watching());
      hooks.apply(ptr::null_mut());
   }

   #[test]
   fn text_hooks_see_decoded_words() {
      let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
      let sink = captured.clone();
      add_text_hook(Box::new(move |_: *mut c_void, texts: &mut Vec<(usize, String)>| {
         *sink.lock().unwrap_or_else(PoisonError::into_inner) = texts.clone();
      }));
      let mut data = words();
      data[7] = u64::from_le_bytes(*b"abcdefgh");
      HOOKS.apply(ptr(&mut data));
      assert_eq!(
         *captured.lock().unwrap_or_else(PoisonError::into_inner),
         vec![(7, "abcdefgh".to_owned())]
      );
   }

   #[test]
   #[cfg(not(target_os = "ios"))]
   fn android_and_host_builds_never_install() {
      // `ios` is compiled under cfg(test) on the host; no inline patch runs.
      assert!(!cfg!(target_os = "ios"));
      assert!(!installed());
   }
}
