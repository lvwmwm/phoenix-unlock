//! The only build-pinned numbers in the iOS bridge.
//!
//! Everything in this file was derived from `PhoenixFatClient` build
//! `4434ca40b8c13222a303851598aaf121` (Discord 357.0 iOS, thin arm64). The
//! runtime checks the LC_UUID before using any address; on another build it
//! falls back to the structural search in [`super::events`] and, failing that,
//! leaves the hook uninstalled with an error naming the build. Do not add raw
//! addresses anywhere else.

/// LC_UUID the pinned addresses below belong to.
pub const PINNED_UUID: &str = "4434ca40b8c13222a303851598aaf121";

/// Unslid vmaddr of the guest trait-object vtable's dispatch slot. Recovered
/// from the live bridge: a trait object at 0x283a5ef90 pointed to vtable
/// 0x10f995700, whose +0x20 held dispatch 0x10e9005e0, phx base 0x10a44c000.
/// The vtable is a Rust static, so this vmaddr is stable across launches.
pub const GUEST_VTABLE_SLOT: u64 = 0x0554_9720;

/// Unslid vmaddr of the Swift→Rust bridge, used only as a cross-check of a
/// discovered dispatch target. Do not patch this function.
pub const BRIDGE: usize = 0x044b_80b8;

/// Unslid vmaddr of the `CATransaction` block invoke built in `applyOps`
/// (`0x34926c`). Ghidra names the block literal `&DAT_00159618`; its context
/// carries the rendered UI strings as Swift inline small strings. Code patch,
/// not a data slot: jailbroken/Dobby only.
pub const APPLY_OPS_BLOCK: usize = 0x0015_9618;

/// Field offsets inside the live objects. These are Rust/Swift layout facts,
/// not code addresses, and are reused by the build-agnostic structural search.
pub mod field {
   /// `GuestHost.guest`.
   pub const GUEST: u64 = 0x48;
   /// Count and array of 0x50-byte queued view events.
   pub const EVENT_COUNT: u64 = 0x10;
   pub const EVENT_ARRAY: u64 = 0x20;
   /// Batching flag read by the central dispatcher.
   pub const BATCHING: u64 = 0x68;
   /// The Rust trait object `{data, vtable}` inside the guest holder.
   pub const TRAIT: u64 = 0x10;
   pub const TRAIT_VTABLE: u64 = 0x08;
   /// Vtable slot holding `dispatch(data, bytes, len, out)`.
   pub const VTABLE_DISPATCH: u64 = 0x20;
   /// Stride of the event records at `GuestHost + EVENT_ARRAY`.
   pub const EVENT_STRIDE: usize = 0x50;
}
