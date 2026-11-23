//! Scaffolding for a native Settings → Phoenix Unlocker page on iOS.
//!
//! Android's layouts do not describe Phoenix's iOS view tree. Nothing is
//! emitted until a [`LayoutProvider`] with captured iOS ops is installed.
//!
//! Capture needed before a page can render:
//! 1. The settings-screen ops batch (0xa8-byte records with tags and words)
//!    containing the "Log Out" row.
//! 2. A page-open batch, for the page root and back button.
//! 3. The inbound tap frame (`0x7dce2c`, x1/x2) to find our accessibility id.
//! 4. iOS icons, colors and sizes; Android's theme values do not apply.

use std::{
   panic::{
      AssertUnwindSafe,
      catch_unwind,
   },
   sync::{
      Arc,
      Mutex,
      MutexGuard,
      OnceLock,
      PoisonError,
      atomic::{
         AtomicBool,
         Ordering,
      },
      mpsc::{
         self,
         Sender,
      },
   },
};

use crate::ops::{
   self,
   Op,
   OpsHook,
   OpsVec,
};
use super::events::{
   self,
   Action as EventAction,
   EventSink,
};

/// Marker identifying the settings screen; override once captured.
const DEFAULT_MARKER: &str = "settings.row.logout";
/// Accessibility-id prefix for our rows, mirroring Android's convention.
pub const ROW_PREFIX: &str = "phoenix-";

/// A row the user can press on the native page.
#[derive(Clone)]
pub struct Row {
   pub id:      String,
   pub title:   String,
   pub pressed: Arc<dyn Fn() + Send + Sync>,
}

/// Turns captured iOS layouts into ops records; `None` for uncaptured layouts.
pub trait LayoutProvider: Send + Sync {
   /// Ops for one row.
   fn row(&self, row: &Row) -> Option<Vec<Op>>;
   /// Ops for the page pushed by the main row.
   fn page(&self, title: &str, rows: &[Row]) -> Option<Vec<Op>>;
}

/// Emits nothing: no layouts have been captured.
struct NoLayouts;

impl LayoutProvider for NoLayouts {
   fn row(&self, _: &Row) -> Option<Vec<Op>> {
      None
   }

   fn page(&self, _: &str, _: &[Row]) -> Option<Vec<Op>> {
      None
   }
}

enum Job {
   /// A row's callback, queued off the event thread.
   Press(usize),
}

struct Settings {
   rows:      Vec<Row>,
   provider:  Arc<dyn LayoutProvider>,
   marker:    String,
}

static SETTINGS: OnceLock<Mutex<Settings>> = OnceLock::new();
static WORKER: OnceLock<Sender<Job>> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);

fn default_settings() -> Settings {
   Settings {
      rows: Vec::new(),
      provider: Arc::new(NoLayouts),
      marker: DEFAULT_MARKER.to_owned(),
   }
}

fn settings() -> MutexGuard<'static, Settings> {
   SETTINGS
      .get_or_init(|| Mutex::new(default_settings()))
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
}

/// Adds a row with its accessibility id and press callback.
pub fn add_row(
   id: impl Into<String>,
   title: impl Into<String>,
   pressed: Box<dyn Fn() + Send + Sync>,
) {
   let id = id.into();
   let mut state = settings();
   let index = state.rows.len();
   let pressed = Arc::from(pressed);
   state.rows.push(Row {
      id: id.clone(),
      title: title.into(),
      pressed,
   });
   drop(state);
   events::ROUTER.register(id, Box::new(move || {
      if let Some(worker) = WORKER.get()
         && worker.send(Job::Press(index)).is_err()
      {
         log::warn!("ios settings: the worker stopped");
      }
   }));
}

/// Supplies the captured iOS layouts.
pub fn set_layout_provider(provider: Box<dyn LayoutProvider>) {
   settings().provider = Arc::from(provider);
}

/// Changes the byte marker used to detect the settings screen.
pub fn set_settings_marker(marker: impl Into<String>) {
   settings().marker = marker.into();
}

/// Installs the hooks; only the first call has an effect.
pub fn start() {
   if STARTED.swap(true, Ordering::AcqRel) {
      return;
   }
   drop(settings());

   // Byte matches are hints, so matched frames still reach Phoenix.
   events::ROUTER.set_drop_matched(false);
   events::add_sink(Box::new(RouterSink));
   ops::install(Box::new(SettingsSink));

   let (sender, receiver) = mpsc::channel::<Job>();
   let _ = WORKER.set(sender);
   std::thread::spawn(move || {
      for Job::Press(index) in receiver {
         let callback = settings().rows.get(index).map(|row| Arc::clone(&row.pressed));
         if let Some(callback) = callback
            && catch_unwind(AssertUnwindSafe(|| callback())).is_err()
         {
            log::warn!("ios settings: a row callback panicked");
         }
      }
   });
   log::warn!(
      "ios settings: no captured layouts installed; the Phoenix Unlocker row cannot render \
       until a LayoutProvider is supplied (see this module's capture checklist)"
   );
}

struct RouterSink;

impl EventSink for RouterSink {
   fn dispatch(&self, frame: &[u8]) -> EventAction {
      events::ROUTER.dispatch(frame)
   }
}

struct SettingsSink;

impl OpsHook for SettingsSink {
   fn ops(&self, _event: &str, ops: &mut OpsVec) {
      let (marker, provider, rows) = {
         let state = settings();
         (state.marker.clone(), Arc::clone(&state.provider), state.rows.clone())
      };
      let records = unsafe { ops.records() };
      if !contains(records, marker.as_bytes()) {
         return;
      }
      let mut additions = Vec::new();
      for row in &rows {
         if let Some(nodes) = provider.row(row) {
            additions.extend(nodes);
         }
      }
      if additions.is_empty() {
         log::debug!("ios settings: the provider returned no rows");
         return;
      }
      for node in additions {
         if !ops.push(node) {
            log::warn!(
               "ios settings: the guest reserved no room for a row (len {}, cap {}); \
                rewriting an existing record is required until a grow helper is proven safe",
               ops.len,
               ops.cap
            );
            break;
         }
      }
   }
}

/// Looks for the marker across the batch's bytes.
fn contains(ops: &[Op], needle: &[u8]) -> bool {
   if needle.is_empty() {
      return false;
   }
   let mut bytes = Vec::with_capacity(ops.len() * std::mem::size_of::<Op>());
   for op in ops {
      for word in op.words() {
         bytes.extend_from_slice(&word.to_ne_bytes());
      }
   }
   bytes.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn marker_needs_a_full_stream() {
      let mut first = Op::new(0x19);
      first.0[1] = u64::from_ne_bytes(*b"settings");
      first.0[2] = u64::from_ne_bytes(*b".row.abc");
      assert!(contains(&[first], b"settings.row."));
   }

   #[test]
   fn no_provider_emits_nothing() {
      let settings = default_settings();
      assert!(settings.provider.row(&Row {
         id: "x".into(),
         title: "x".into(),
         pressed: Arc::new(|| {}),
      }).is_none());
   }
}
