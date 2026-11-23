//! View of the native UI-op vector Phoenix passes to a gateway handler.
//!
//! On iOS the third handler argument is a live `Vec<Op>`: `{cap, data, len}`
//! with 0xa8-byte records whose first word is a tag. Hooks get a mutable view;
//! records belong to the guest allocator, so only in-place rewrites, drops and
//! appends within existing capacity are safe. Records have drop glue — a hook
//! must not write owned fields it has not captured.

#[cfg(target_os = "ios")]
use std::cell::Cell;

use std::{
   ffi::c_void,
   mem::size_of,
   panic::{
      AssertUnwindSafe,
      catch_unwind,
   },
   ptr,
   slice,
   sync::{
      PoisonError,
      RwLock,
      atomic::{
         AtomicBool,
         Ordering,
      },
   },
};

/// Words in one guest `Op` record.
pub const OP_WORDS: usize = 21;
/// Size of one guest `Op` record.
pub const OP_SIZE: usize = OP_WORDS * size_of::<u64>();

const _: () = assert!(OP_SIZE == 0xa8);
const _: () = assert!(size_of::<usize>() == 8, "the guest ABI is 64-bit");

/// One guest UI op: a tag at word 0 followed by tag-specific payload words.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op(pub [u64; OP_WORDS]);

impl Op {
   /// An all-zero record with `tag` set, ready for a hook to fill in.
   #[must_use]
   pub const fn new(tag: u64) -> Self {
      let mut words = [0; OP_WORDS];
      words[0] = tag;
      Self(words)
   }

   #[must_use]
   pub const fn tag(&self) -> u64 {
      self.0[0]
   }

   #[must_use]
   pub fn words(&self) -> &[u64; OP_WORDS] {
      &self.0
   }

   pub fn words_mut(&mut self) -> &mut [u64; OP_WORDS] {
      &mut self.0
   }
}

/// The guest's `Vec<Op>` header: `{cap, data, len}`.
#[repr(C)]
#[derive(Debug)]
pub struct OpsVec {
   pub cap:  u64,
   pub data: *mut Op,
   pub len:  u64,
}

const _: () = assert!(size_of::<OpsVec>() == 3 * size_of::<usize>());

impl OpsVec {
   /// Builds a view over a caller-owned header.
   ///
   /// # Safety
   ///
   /// `ptr` must point to a live `Vec<Op>` header for the returned lifetime.
   #[must_use]
   pub unsafe fn from_ptr<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
      (!ptr.is_null()).then(|| unsafe { &mut *ptr.cast::<Self>() })
   }

   /// A header over test-owned records. `cap` must be at least `ops.len()`.
   #[must_use]
   pub fn from_records(cap: u64, ops: &mut [Op]) -> Self {
      Self {
         cap,
         data: ops.as_mut_ptr(),
         len: ops.len() as u64,
      }
   }

   #[must_use]
   pub fn is_empty(&self) -> bool {
      self.len == 0
   }

   /// # Safety
   ///
   /// `data` and `len` must be the live Vec's fields.
   #[must_use]
   pub unsafe fn records(&self) -> &[Op] {
      if self.data.is_null() {
         return &[];
      }
      // SAFETY: forwarded from the caller's invariant.
      unsafe { slice::from_raw_parts(self.data, self.len as usize) }
   }

   /// # Safety
   ///
   /// `data` and `len` must be the live Vec's fields, and no other reference
   /// to the records may be alive.
   pub unsafe fn records_mut(&mut self) -> &mut [Op] {
      if self.data.is_null() {
         return &mut [];
      }
      // SAFETY: forwarded from the caller's invariant.
      unsafe { slice::from_raw_parts_mut(self.data, self.len as usize) }
   }

   /// Drops the batch without freeing the records.
   pub fn clear(&mut self) {
      self.len = 0;
   }

   /// Keeps only accepted records, compacting in place.
   pub fn retain(&mut self, mut keep: impl FnMut(&Op) -> bool) {
      let mut out = 0usize;
      for index in 0..self.len as usize {
         // SAFETY: `index` is below the Vec's length.
         let op = unsafe { &*self.data.add(index) };
         if keep(op) {
            if out != index {
               // SAFETY: `out < index`, both below the length, non-overlapping
               // in the forward copy direction.
               unsafe { ptr::copy_nonoverlapping(self.data.add(index), self.data.add(out), 1) };
            }
            out += 1;
         }
      }
      self.len = out as u64;
   }

   /// Replaces one record in place. Returns false for an out-of-range index.
   pub fn replace(&mut self, index: usize, op: Op) -> bool {
      if index >= self.len as usize || self.data.is_null() {
         return false;
      }
      // SAFETY: `index` is below the Vec's length.
      unsafe { ptr::write(self.data.add(index), op) };
      true
   }

   /// Appends within existing capacity; the guest's grow helper is not called.
   pub fn push(&mut self, op: Op) -> bool {
      if self.data.is_null() || self.len >= self.cap {
         return false;
      }
      // SAFETY: `len < cap`, so the slot is reserved and initialized by the
      // guest before any hook runs.
      unsafe { ptr::write(self.data.add(self.len as usize), op) };
      self.len += 1;
      true
   }
}

/// Receives the ops a handler appended, after it has run.
pub trait OpsHook: Send + Sync {
   fn ops(&self, event: &str, ops: &mut OpsVec);
}

/// A thread-safe hook registry.
pub struct OpsHooks {
   hooks:    RwLock<Vec<Box<dyn OpsHook>>>,
   watching: AtomicBool,
}

impl OpsHooks {
   #[must_use]
   pub const fn new() -> Self {
      Self {
         hooks:    RwLock::new(Vec::new()),
         watching: AtomicBool::new(false),
      }
   }

   pub fn install(&self, hook: Box<dyn OpsHook>) {
      self.hooks
         .write()
         .unwrap_or_else(PoisonError::into_inner)
         .push(hook);
      self.watching.store(true, Ordering::Release);
   }

   /// The detour's fast path: one atomic load when nothing is installed.
   #[must_use]
   pub fn watching(&self) -> bool {
      self.watching.load(Ordering::Acquire)
   }

   /// Runs every sink, catching panics.
   pub fn apply(&self, event: &str, ops: &mut OpsVec) {
      if !self.watching() {
         return;
      }
      let hooks = self
         .hooks
         .read()
         .unwrap_or_else(PoisonError::into_inner);
      for hook in hooks.iter() {
         if catch_unwind(AssertUnwindSafe(|| hook.ops(event, ops))).is_err() {
            log::warn!("ops: a hook panicked on {event}, keeping its earlier changes");
         }
      }
   }
}

impl Default for OpsHooks {
   fn default() -> Self {
      Self::new()
   }
}

pub static HOOKS: OpsHooks = OpsHooks::new();

/// Adds a process-wide ops hook. Safe before or after the runtime starts.
pub fn install(hook: Box<dyn OpsHook>) {
   HOOKS.install(hook);
}

#[cfg(target_os = "ios")]
thread_local! {
   static IN_OPS: Cell<bool> = const { Cell::new(false) };
}

/// Runs hooks on the batch the handler just filled (iOS only).
#[cfg(target_os = "ios")]
pub(crate) fn after_handler(ctx: *mut c_void, event: &str) {
   if !HOOKS.watching() || ctx.is_null() || IN_OPS.get() {
      return;
   }
   IN_OPS.set(true);
   let outcome = catch_unwind(AssertUnwindSafe(|| {
      // SAFETY: `ctx` is the guest handler's live `&mut Vec<Op>`, still owned
      // by the caller of the detour while we are on its stack.
      if let Some(ops) = unsafe { OpsVec::from_ptr(ctx) } {
         HOOKS.apply(event, ops);
      }
   }));
   IN_OPS.set(false);
   if outcome.is_err() {
      log::error!("ops: the hook batch panicked, the host keeps the original ops");
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   struct Rewrite;
   impl OpsHook for Rewrite {
      fn ops(&self, event: &str, ops: &mut OpsVec) {
         assert_eq!(event, "MESSAGE_CREATE");
         // SAFETY: the backing records outlive this call.
         for op in unsafe { ops.records_mut() } {
            if op.tag() == 0x42 {
               op.0[0] = 0x56;
            }
         }
      }
   }

   struct DropViews;
   impl OpsHook for DropViews {
      fn ops(&self, _: &str, ops: &mut OpsVec) {
         ops.retain(|op| op.tag() != 0x19);
      }
   }

   struct Panics;
   impl OpsHook for Panics {
      fn ops(&self, _: &str, _: &mut OpsVec) {
         panic!("test");
      }
   }

   #[test]
   fn record_layout() {
      assert_eq!(size_of::<Op>(), 0xa8);
      assert_eq!(size_of::<OpsVec>(), 24);
      assert_eq!(Op::new(0x42).tag(), 0x42);
   }

   #[test]
   fn push_respects_capacity() {
      let mut records = [Op::new(0); 2];
      // Reserve two slots but start with no records, like a freshly grown
      // guest Vec.
      let mut ops = OpsVec {
         cap: 2,
         data: records.as_mut_ptr(),
         len: 0,
      };
      assert!(ops.push(Op::new(0x19)));
      assert!(ops.push(Op::new(0x42)));
      assert!(!ops.push(Op::new(0x56)), "no growth helper from a hook");
      assert_eq!(ops.len, 2);
   }

   #[test]
   fn clear_and_retain() {
      let mut records = [Op::new(0x19), Op::new(0x42), Op::new(0x19)];
      let mut ops = OpsVec::from_records(3, &mut records);
      ops.retain(|op| op.tag() != 0x19);
      assert_eq!(ops.len, 1);
      assert_eq!(unsafe { ops.records() }[0].tag(), 0x42);
      ops.clear();
      assert!(ops.is_empty());
   }

   #[test]
   fn hooks_chain_and_survive_panics() {
      let hooks = OpsHooks::new();
      hooks.install(Box::new(Rewrite));
      hooks.install(Box::new(Panics));
      hooks.install(Box::new(DropViews));
      let mut records = [Op::new(0x19), Op::new(0x42)];
      let mut ops = OpsVec::from_records(2, &mut records);
      hooks.apply("MESSAGE_CREATE", &mut ops);
      let tags = unsafe { ops.records() }
         .iter()
         .map(Op::tag)
         .collect::<Vec<_>>();
      assert_eq!(tags, [0x56], "rewritten 0x42, dropped 0x19");
   }

   #[test]
   fn no_hooks_is_no_work() {
      let hooks = OpsHooks::new();
      assert!(!hooks.watching());
      let mut records = [Op::new(0x42)];
      let mut ops = OpsVec::from_records(1, &mut records);
      hooks.apply("MESSAGE_CREATE", &mut ops);
      assert_eq!(unsafe { ops.records() }[0].tag(), 0x42);
   }
}
