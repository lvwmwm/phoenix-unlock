//! iOS-only bridge modules. All of the data-level plumbing lives here so the
//! Android runtime stays byte-identical; the ops view itself is compiled on
//! every target (see `crate::ops`).

pub mod block;
pub mod events;
pub mod layout;
pub mod settings;

use phoenix_hook::Image;

/// Starts the iOS hooks after the runtime state has been published.
pub fn start(image: &'static Image<'static>) {
   events::prepare(image);
   block::start(image);
   settings::start();
}
