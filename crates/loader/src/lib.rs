//! `libphoenix.so`, injected through a `DT_NEEDED` entry on Android and as a
//! dylib on iOS.
//!
//! The constructor runs once the host library is mapped and relocated, before
//! the host's own constructors and before the app touches the gateway, so hooks
//! are in place for the first dispatch. Plugins come from the bundle the
//! patcher stores beside this library, then from `$PHOENIX_HOME/plugins`.
//! `$PHOENIX_HOME` defaults to the app's `files/phoenix` on Android.

use std::{
   collections::BTreeMap,
   env,
   ffi::{
      CStr,
      c_void,
   },
   fs::{
      self,
      File,
   },
   io::{
      ErrorKind,
      Read,
   },
   panic::{
      self,
      AssertUnwindSafe,
   },
   path::{
      Path,
      PathBuf,
   },
};

use misstep::ResultExt;
use phoenix_runtime::{
   Plugin,
   console::Tee,
};
use phoenix_sigs::PLUGIN_BUNDLE;
use zip::{
   ZipArchive,
   result::ZipError,
};

#[used]
#[cfg_attr(not(target_vendor = "apple"), unsafe(link_section = ".init_array"))]
#[cfg_attr(
   target_vendor = "apple",
   unsafe(link_section = "__DATA,__mod_init_func")
)]
static CONSTRUCTOR: extern "C" fn() = init;

extern "C" fn init() {
   logging();
   // Unwinding out of a constructor aborts the host, so a bug here costs
   // plugins, not the app.
   match panic::catch_unwind(AssertUnwindSafe(|| {
      phoenix_runtime::start(home(), bundled())
   })) {
      Ok(Ok(started)) => {
         log::info!(
            "phoenix started on {} ({}), plugins: {:?}",
            started.target,
            started.build.unwrap_or("unknown build, portable rules"),
            started.plugins,
         );
      },
      Ok(Err(err)) => log::error!("phoenix did not start: {err}"),
      Err(_) => log::error!("phoenix panicked while starting"),
   }
}

fn home() -> PathBuf {
   if let Some(home) = env::var_os("PHOENIX_HOME") {
      return PathBuf::from(home);
   }
   #[cfg(target_vendor = "apple")]
   {
      // The app's Documents directory inside its sandbox.
      if let Ok(dir) = std::env::var("HOME") {
         return PathBuf::from(dir).join("Documents/phoenix");
      }
      return PathBuf::from("/Documents/phoenix");
   }
   // /proc/self/cmdline starts with the package name, plus `:process` for
   // secondary processes.
   let package = fs::read("/proc/self/cmdline")
      .ok()
      .and_then(|cmdline| {
         let name = cmdline.split(|byte| *byte == 0).next()?.to_vec();
         String::from_utf8(name).ok()
      })
      .map_or_default(|name| name.split(':').next().unwrap_or_default().to_owned());
   PathBuf::from(format!("/data/data/{package}/files/phoenix"))
}

fn bundled() -> Vec<Plugin> {
   match read_bundle() {
      Ok(plugins) => plugins,
      Err(err) => {
         log::error!("plugin bundle: {err}");
         Vec::new()
      },
   }
}

/// Reads [`PLUGIN_BUNDLE`] from beside this library. Android maps native
/// libraries straight out of the APK, so `dladdr` names `<apk>!/lib/<abi>/...`
/// and the bundle is a stored entry in the same split.
fn read_bundle() -> misstep::Result<Vec<Plugin>> {
   let mut info = libc::Dl_info {
      dli_fname: std::ptr::null(),
      dli_fbase: std::ptr::null_mut(),
      dli_sname: std::ptr::null(),
      dli_saddr: std::ptr::null_mut(),
   };
   // SAFETY: dladdr fills `info` for an address inside a loaded module.
   if unsafe { libc::dladdr(init as *const c_void, &raw mut info) } == 0 || info.dli_fname.is_null()
   {
      return Ok(Vec::new());
   }
   // SAFETY: dli_fname is NUL-terminated and lives as long as the module.
   let path = unsafe { CStr::from_ptr(info.dli_fname) }.to_str()?;

   let bytes = if let Some((apk, inner)) = path.split_once("!/") {
      let dir = inner.rsplit_once('/').map_or("", |(dir, _)| dir);
      let mut archive =
         ZipArchive::new(File::open(apk).with_context(|| format!("opening {apk}"))?)?;
      let mut entry = match archive.by_name(&format!("{dir}/{PLUGIN_BUNDLE}")) {
         Ok(entry) => entry,
         Err(ZipError::FileNotFound) => return Ok(Vec::new()),
         Err(err) => return Err(err.into()),
      };
      let mut bytes = Vec::new();
      entry.read_to_end(&mut bytes)?;
      bytes
   } else {
      match fs::read(Path::new(path).with_file_name(PLUGIN_BUNDLE)) {
         Ok(bytes) => bytes,
         Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
         Err(err) => return Err(err.into()),
      }
   };
   let plugins: BTreeMap<String, String> = serde_json::from_slice(&bytes)?;
   Ok(plugins
      .into_iter()
      .map(|(name, source)| Plugin { name, source })
      .collect())
}

#[cfg(target_os = "android")]
fn logging() {
   let config = android_logger::Config::default()
      .with_tag("phoenix")
      .with_max_level(log::LevelFilter::Info);
   let logger = Tee(android_logger::AndroidLogger::new(config));
   if log::set_logger(Box::leak(Box::new(logger))).is_ok() {
      log::set_max_level(log::LevelFilter::Info);
   }
}

#[cfg(not(target_os = "android"))]
fn logging() {
   struct Stderr;

   impl log::Log for Stderr {
      fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
         metadata.level() <= log::Level::Info
      }

      fn log(&self, record: &log::Record<'_>) {
         if self.enabled(record.metadata()) {
            eprintln!("[phoenix {}] {}", record.level(), record.args());
         }
      }

      fn flush(&self) {}
   }

   if log::set_logger(&Tee(Stderr)).is_ok() {
      log::set_max_level(log::LevelFilter::Info);
   }
}
