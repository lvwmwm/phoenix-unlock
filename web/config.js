// CORS proxy in front of tracker.vendetta.rocks (see worker/proxy.js). Empty = manual file mode only.
export const PROXY = 'https://phoenix-apk-proxy.mantikafasi.workers.dev';
// Builds the patcher was verified against. Newer builds are tried too; the patcher refuses if anchors move.
export const VERIFIED = [356207];
// Decrypted Discord 357.0 IPA, split for same-origin fetching on Pages.
export const IOS_CHUNKS = ['ios/chunks/part-0.bin', 'ios/chunks/part-1.bin', 'ios/chunks/part-2.bin'];
export const IOS_CHUNK_SIZE = 80000000;
export const IOS_SOURCE_SIZE = 233856341;
