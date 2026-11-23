//! Function hooks and signature scanning for phoenix.
//!
//! - [`Hook`] is the inline-hook interface. [`Inline`] picks the backend for
//!   the target, `ShadowHook` on Android ARM and Dobby everywhere else (iOS,
//!   x86_64 Android and Linux).
//! - [`PltHook`] rewrites GOT entries through `ByteHook` on Android.
//! - [`Image`] views a loaded ELF module, scans it for [`Pattern`]s, and swaps
//!   pointers in its read-only data.

use std::{
   ffi::c_void,
   ptr::NonNull,
};

#[cfg(not(any(windows, target_vendor = "apple", all(
   target_os = "android",
   any(target_arch = "aarch64", target_arch = "arm")
))))]
mod dobby;
#[cfg(target_vendor = "apple")]
mod noop;
// On Windows only the parts the host-side patcher reads build; the rest needs dl_iterate_phdr.
#[cfg_attr(windows, allow(dead_code, unused_imports))]
mod image;
mod pattern;
#[cfg(target_os = "android")] mod plt;
#[cfg(all(
   target_os = "android",
   any(target_arch = "aarch64", target_arch = "arm")
))]
mod shadowhook;

#[cfg(not(any(windows, target_vendor = "apple", all(
   target_os = "android",
   any(target_arch = "aarch64", target_arch = "arm")
))))]
pub use dobby::Dobby as Inline;
#[cfg(target_vendor = "apple")]
pub use noop::Noop as Inline;
#[cfg(unix)] pub use image::swap_words;
pub use image::{
   BuildId,
   Image,
   Segment,
};
pub use pattern::Pattern;
#[cfg(target_os = "android")] pub use plt::PltHook;
#[cfg(all(
   target_os = "android",
   any(target_arch = "aarch64", target_arch = "arm")
))]
pub use shadowhook::ShadowHook as Inline;

#[derive(Debug, flub::Error)]
pub enum Error {
   #[error("{backend} failed to initialize: {message}")]
   Init {
      backend: &'static str,
      message: String,
   },
   #[error("{backend} could not hook {target:#x}: {message}")]
   Attach {
      backend: &'static str,
      target:  usize,
      message: String,
   },
   #[error("{backend} could not unhook {target:#x}: {message}")]
   Detach {
      backend: &'static str,
      target:  usize,
      message: String,
   },
   #[error("{addr:#x} is not in any mapping")]
   Unmapped { addr: usize },
   #[error("mprotect {addr:#x}")]
   Protect {
      addr:   usize,
      #[source]
      source: std::io::Error,
   },
}

/// An installed inline hook. Dropping it leaves the hook in place, use
/// [`Hook::detach`] to restore the original code.
pub trait Hook: Sized + Send + Sync {
   /// Redirects calls to `target` into `detour`.
   ///
   /// # Safety
   ///
   /// `target` is the first instruction of a function, and `detour` has the
   /// same ABI.
   unsafe fn attach(target: NonNull<c_void>, detour: NonNull<c_void>) -> Result<Self, Error>;

   /// Entry point that runs the original function body.
   fn original(&self) -> NonNull<c_void>;

   /// # Safety
   ///
   /// No thread is inside the detour or holds the [`Hook::original`]
   /// trampoline.
   unsafe fn detach(self) -> Result<(), Error>;
}
