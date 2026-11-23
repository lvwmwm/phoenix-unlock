use std::borrow::Cow;

use crate::{
   Anchor,
   Build,
   BuildId,
   GATEWAY_HANDLER_FIELD,
   Gateway,
   Pattern,
   Sig,
};

/// A gateway rule, the handler's prologue in this build plus the portable
/// registry lookup by the event's name.
macro_rules! gateway {
   ($event:literal, $pattern:literal) => {
      Gateway {
         sig: Sig::new($event, &[
            Anchor::Code {
               pattern: Pattern::ida($pattern),
               offset:  0,
            },
            Anchor::Table {
               key:   Cow::Borrowed($event),
               field: GATEWAY_HANDLER_FIELD,
            },
         ]),
      }
   };
}

pub static BUILDS: &[Build] = &[
   Build {
      id:      BuildId::hex("4434ca40b8c13222a303851598aaf121"),
      label:   "Phoenix 357.0 iOS (PhoenixFatClient)",
      library: "PhoenixFatClient",
      gateway: &[],
   },
   Build {
      id:      BuildId::hex("c4b06db4b1ec3311e9a7e10238d646a62a484c5f"),
      label:   "Phoenix 356.7 (356207) arm64-v8a",
      library: "liblibdiscord_wasm_host.so",
      gateway: &[
         gateway!(
            "MESSAGE_CREATE",
            "FD 7B BA A9 FC 6F 01 A9 FA 67 02 A9 F8 5F 03 A9 F6 57 04 A9 F4 4F 05 A9 FD 03 00 91 \
             FF 07 40 D1 FF 03 00 F9 FF 43 11 D1 F8 03 08 AA"
         ),
         gateway!(
            "MESSAGE_UPDATE",
            "FD 7B BA A9 FC 6F 01 A9 FA 67 02 A9 F8 5F 03 A9 F6 57 04 A9 F4 4F 05 A9 FD 03 00 91 \
             FF 07 40 D1 FF 03 00 F9 FF 03 05 D1 E0 1F 00 F9"
         ),
         gateway!(
            "MESSAGE_DELETE",
            "FD 7B BA A9 FC 6F 01 A9 FA 67 02 A9 F8 5F 03 A9 F6 57 04 A9 F4 4F 05 A9 FD 03 00 91 \
             FF 43 1A D1 FC 03 00 AA"
         ),
      ],
   },
   Build {
      id:      BuildId::hex("9c88d12ebb6190020378fc03cee74952f7f1c3bb"),
      label:   "Phoenix 356.7 (356207) x86_64",
      library: "liblibdiscord_wasm_host.so",
      gateway: &[
         gateway!(
            "MESSAGE_CREATE",
            "55 41 57 41 56 41 55 41 54 53 48 81 EC 00 10 00 00 48 C7 04 24 00 00 00 00 48 81 EC \
             58 04 00 00 49 89 CC"
         ),
         gateway!(
            "MESSAGE_UPDATE",
            "55 41 57 41 56 41 55 41 54 53 48 81 EC 00 10 00 00 48 C7 04 24 00 00 00 00 48 81 EC \
             48 01 00 00 49 89 CC 48 89 D3"
         ),
         gateway!(
            "MESSAGE_DELETE",
            "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 06 00 00 48 89 CD"
         ),
      ],
   },
   // Stand-in builds from the pinned toolchain in flake.lock. A toolchain bump
   // changes the ID, and the stand-in then resolves through the portable rule
   // until sigscan re-adds it.
   Build {
      id:      BuildId::hex("408ec6483ec56a1912195be611e63fce5b8d068c"),
      label:   "stand-in x86_64-unknown-linux-gnu",
      library: "libstand_in.so",
      gateway: &[gateway!(
         "MESSAGE_CREATE",
         "41 57 41 56 41 54 53 48 81 EC C8 00 00 00 49 89 F6 48 89 FB 48 8B 72 10"
      )],
   },
   Build {
      id:      BuildId::hex("1e73524ceb72d8d81802dc39982d473d23890d42"),
      label:   "stand-in aarch64-linux-android",
      library: "libstand_in.so",
      gateway: &[gateway!(
         "MESSAGE_CREATE",
         "FF C3 03 D1 FD 7B 0C A9 F5 6B 00 F9 F4 4F 0E A9 FD 03 03 91 29 08 41 A9 F4 03 00 AA F3 \
          03 08 AA"
      )],
   },
];
