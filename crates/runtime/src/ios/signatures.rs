//! Pure byte signatures for the iOS Swift→Rust bridge. No build-pinned
//! addresses: the matcher works on any image bytes and is host-testable.

/// One AArch64 instruction word. `None` matches any word.
pub(crate) type Words = &'static [Option<u32>];

/// `ldp x8,x9,[x0]; cmp x2,#0; csinc x1,x1,xzr,ne; ldr x9,[x9,#0x20];
/// mov x0,x8; blr x9`, with `mov x19,x3` and a variable prologue in front.
/// The first four words are wildcards (stack-frame size/offsets may shift);
/// the core is exact. Verified: one match in PhoenixFatClient 357.0 at
/// unslid `0x44b80b8` (see `verify_bridge_signature.py`).
pub(crate) const BRIDGE: Words = &[
   None,              // sub sp, sp, #imm
   None,              // stp x20, x19, [sp, #imm]
   None,              // stp x29, x30, [sp, #imm]
   None,              // add x29, sp, #imm
   Some(0xaa03_03f3), // mov x19, x3
   Some(0xa940_2408), // ldp x8, x9, [x0]
   Some(0xf100_005f), // cmp x2, #0
   Some(0x9a9f_1421), // csinc x1, x1, xzr, ne
   Some(0xf940_1129), // ldr x9, [x9, #0x20]
   Some(0xaa08_03e0), // mov x0, x8
   Some(0xd63f_0120), // blr x9
];

/// Byte offsets in `bytes` where `words` matches at a 4-byte boundary.
pub(crate) fn find(bytes: &[u8], words: &[Option<u32>]) -> Vec<usize> {
   let width = words.len() * 4;
   if bytes.len() < width {
      return Vec::new();
   }
   (0..=bytes.len() - width)
      .step_by(4)
      .filter(|&at| {
         words.iter().enumerate().all(|(index, word)| match word {
            None => true,
            Some(expected) => {
               let at = at + index * 4;
               u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) == *expected
            },
         })
      })
      .collect()
}

#[cfg(test)]
mod tests {
   use super::*;

   fn synthetic() -> Vec<u8> {
      let words = [
         0xd100_c3ff_u32, // sub sp, sp, #0x30
         0xa901_4ff4,     // stp x20, x19, [sp, #0x10]
         0xa902_7bfd,     // stp x29, x30, [sp, #0x20]
         0x9100_83fd,     // add x29, sp, #0x20
         0xaa03_03f3,     // mov x19, x3
         0xa940_2408,     // ldp x8, x9, [x0]
         0xf100_005f,     // cmp x2, #0
         0x9a9f_1421,     // csinc x1, x1, xzr, ne
         0xf940_1129,     // ldr x9, [x9, #0x20]
         0xaa08_03e0,     // mov x0, x8
         0xd63f_0120,     // blr x9
      ];
      let mut bytes = vec![0x90; 4 + words.len() * 4 + 4];
      for (index, word) in words.iter().enumerate() {
         bytes[4 + index * 4..8 + index * 4].copy_from_slice(&word.to_le_bytes());
      }
      bytes
   }

   #[test]
   fn finds_bridge_in_synthetic_bytes() {
      assert_eq!(find(&synthetic(), BRIDGE), vec![4]);
   }

   #[test]
   fn wildcard_prologue_still_matches() {
      let mut bytes = synthetic();
      bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
      assert_eq!(find(&bytes, BRIDGE), vec![4]);
   }

   #[test]
   fn wrong_core_does_not_match() {
      let mut bytes = synthetic();
      // Clobber the `ldr x9,[x9,#0x20]` word.
      bytes[4 + 8 * 4..8 + 8 * 4].copy_from_slice(&0u32.to_le_bytes());
      assert!(find(&bytes, BRIDGE).is_empty());
   }

   #[test]
   fn unaligned_matches_are_ignored() {
      let mut bytes = vec![0x90; 64];
      for (index, word) in BRIDGE.iter().enumerate() {
         let at = 1 + index * 4;
         bytes[at..at + 4].copy_from_slice(&word.unwrap_or(0).to_le_bytes());
      }
      assert!(find(&bytes, BRIDGE).is_empty());
   }

   #[test]
   fn short_input_is_empty() {
      assert!(find(&[0u8; 8], BRIDGE).is_empty());
   }
}
