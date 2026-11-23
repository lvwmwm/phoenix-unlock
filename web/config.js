// CORS proxy in front of tracker.vendetta.rocks (see worker/proxy.js). Empty = manual file mode only.
export const PROXY = 'https://phoenix-apk-proxy.mantikafasi.workers.dev';
// Builds the patcher was verified against. Newer builds are tried too; the patcher refuses if anchors move.
export const VERIFIED = [356207];
// Set to '' to disable the built-in IPA.
export const IOS_DEFAULT_IPA = 'ios/discord-357.0-decrypted.ipa';
export const IOS_DEFAULT_NAME = 'Discord 357.0 (hybrid, decrypted)';
