// CORS proxy in front of tracker.vendetta.rocks (see worker/proxy.js). Empty = manual file mode only.
export const PROXY = 'https://phoenix-apk-proxy.mantikafasi.workers.dev';
// Builds the patcher was verified against. Newer builds are tried too; the patcher refuses if anchors move.
export const VERIFIED = [356207];
// Decrypted Discord 357.0 IPA — the patch target, not a pre-patched binary.
export const IOS_SOURCE_URL = 'https://github.com/lvwmwm/phoenix-unlock/releases/download/ios-357.0/Discord_357.0_1.12.2_1795405346.ipa';
export const IOS_SOURCE_SIZE = '223 MB';
