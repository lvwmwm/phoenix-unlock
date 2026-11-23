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

/// Unslid vmaddr of the `__DATA` slot holding the live `GuestHost` instance.
/// Lead from `analysis/swift-bridge`, verified with a watchpoint recipe in
/// `analysis/swift-ops-boundary/event-path.md`.
pub const GUEST_HOST_SLOT: usize = 0x056a_9a00;

/// Unslid vmaddr of the Swift→Rust bridge, used only as a cross-check of a
/// discovered dispatch target. Do not patch this function.
pub const BRIDGE: usize = 0x044b_80b8;

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
