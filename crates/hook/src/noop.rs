//! Stub inline hook for platforms where we only need pointer swaps.

use std::ptr::NonNull;

use crate::Error;

pub struct Noop;

impl Hook for Noop {
   unsafe fn attach(_target: NonNull<std::ffi::c_void>, _detour: NonNull<std::ffi::c_void>) -> Result<Self, Error> {
      Err(Error::Init {
         backend: "noop",
         message: "inline hooks are not available on this target".into(),
      })
   }
   fn original(&self) -> NonNull<std::ffi::c_void> {
      unreachable!()
   }
   unsafe fn detach(self) -> Result<(), Error> { Ok(()) }
}

use crate::Hook;
