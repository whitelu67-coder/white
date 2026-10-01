// ============================================================
// White 密碼本：加解密核心（只用瀏覽器內建的 Web Crypto，不引用任何加密套件）
// ------------------------------------------------------------
// 金鑰架構（v2）：
//   密碼本金鑰 VK：建立時隨機產生的 AES-256 金鑰，所有資料都用它加密
//   主密碼 --PBKDF2-SHA256（600,000 次）＋ saltM--> 256 bits --HKDF-->
//       ・KEK_m：把 VK 加密包起來（wrapM）       → 只在手機上用
//       ・登入鑰 authM：送給 GAS 驗證（GAS 只存雜湊）→ 推不回主密碼，也推不出 KEK_m
//   救援碼（隨機 30 碼）--PBKDF2（100,000 次）＋ saltR--> 一樣分出 KEK_r、authR，另外包一份 VK（wrapR）
//   → 用主密碼或救援碼都能打開；換主密碼只要重新包 VK，不用重新加密所有資料
//
// 每一筆資料分成兩段分別用 VK 加密：
//   摘要 summary：名稱、分類、小分類、網址、備註（解鎖時全部解開，用來顯示清單、搜尋）
//   機密 secret ：帳號、密碼（點開那一筆才向後端要、才解密）
// 每次加密都用新的隨機 IV；並把「這筆的 id + 哪一段」當作附加驗證資料（AAD），
// 避免有人把 A 筆的密文搬到 B 筆、或把摘要跟機密對調還能解得開。
// 瀏覽器、Node.js（測試用）都能載入。
// ============================================================
(function (root) {
  'use strict';

  const PBKDF2_ITERATIONS = 600000;            // 主密碼：OWASP 2023 建議 PBKDF2-SHA256 至少 600,000 次
  const RECOVERY_ITERATIONS = 100000;          // 救援碼本身是 150 bits 的隨機碼，不需要那麼多次
  const SALT_BYTES = 16;
  const IV_BYTES = 12;                         // AES-GCM 建議的 IV 長度
  const RECOVERY_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';   // 31 個字，不含容易看錯的 0 O 1 I L
  const RECOVERY_LENGTH = 30;                  // 30 × log2(31) ≈ 148 bits

  const subtle = (root.crypto && root.crypto.subtle) || null;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function isSupported() {
    return !!(subtle && root.crypto.getRandomValues);
  }

  function randomBytes(n) {
    const b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  /** 從字元集裡隨機挑一個（拒絕取樣，避免偏差） */
  function randomChar(chars) {
    const limit = 256 - (256 % chars.length);
    let x;
    do { x = randomBytes(1)[0]; } while (x >= limit);
    return chars[x % chars.length];
  }

  function toB64(bytes) {
    let s = '';
    const b = new Uint8Array(bytes);
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }

  function fromB64(str) {
    const s = atob(str);
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }

  /** 新的 salt（不用保密，跟密文存在一起） */
  function newSalt() {
    return toB64(randomBytes(SALT_BYTES));
  }

  /** 新一筆資料的 id（用在 AAD，必須在加密前就決定） */
  function newId() {
    return Array.prototype.map.call(randomBytes(8), function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
  }

  // ============================================================
  // 主密碼、救援碼 → KEK（包 VK 用）＋ 登入鑰（給 GAS 驗證）
  // ============================================================

  async function splitKeys(bits, label) {
    const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey', 'deriveBits']);
    const params = function (purpose) {
      return { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('white-vault|' + label + '|' + purpose) };
    };
    const kek = await subtle.deriveKey(params('kek'), hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const auth = await subtle.deriveBits(params('auth'), hk, 256);
    return { kek: kek, auth: toB64(auth) };
  }

  async function pbkdf2Bits(secret, saltB64, iterations) {
    const base = await subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
    return subtle.deriveBits({ name: 'PBKDF2', salt: fromB64(saltB64), iterations: iterations, hash: 'SHA-256' }, base, 256);
  }

  /** 主密碼 → { kek, auth } */
  async function deriveMasterKeys(masterPassword, saltB64, iterations) {
    const bits = await pbkdf2Bits(String(masterPassword).normalize('NFC'), saltB64, iterations || PBKDF2_ITERATIONS);
    return splitKeys(bits, 'master');
  }

  /** 救援碼 → { kek, auth }（大小寫、空白、連字號都不影響） */
  async function deriveRecoveryKeys(code, saltB64) {
    const bits = await pbkdf2Bits(normalizeRecoveryCode(code), saltB64, RECOVERY_ITERATIONS);
    return splitKeys(bits, 'recovery');
  }

  /** 救援碼：30 個字，分成 6 組，例如 K7QM4-XWP9H-… */
  function newRecoveryCode() {
    let s = '';
    for (let i = 0; i < RECOVERY_LENGTH; i++) s += randomChar(RECOVERY_ALPHABET);
    return s.match(/.{5}/g).join('-');
  }

  function normalizeRecoveryCode(code) {
    return String(code || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
  }

  function isValidRecoveryCode(code) {
    const c = normalizeRecoveryCode(code);
    return c.length === RECOVERY_LENGTH && c.split('').every(function (ch) { return RECOVERY_ALPHABET.indexOf(ch) >= 0; });
  }

  // ============================================================
  // 密碼本金鑰 VK：產生、包起來、打開
  // ============================================================

  /** 新的 VK（原始 32 bytes）：只在建立時、重新包裝時短暫存在，用完呼叫 wipe() 清掉 */
  function newVaultKeyRaw() {
    return randomBytes(32);
  }

  function wipe(bytes) {
    if (bytes && bytes.fill) bytes.fill(0);
  }

  /** 用 KEK 把 VK 包起來 → { iv, data } */
  async function wrapVaultKey(kek, vkRaw) {
    const iv = randomBytes(IV_BYTES);
    const data = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode('white-vault|wrap') }, kek, vkRaw);
    return { iv: toB64(iv), data: toB64(data) };
  }

  /** 打開包裝 → VK 原始 bytes（KEK 錯誤會丟出錯誤） */
  async function unwrapVaultKeyRaw(kek, wrap) {
    const raw = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(wrap.iv), additionalData: enc.encode('white-vault|wrap') }, kek, fromB64(wrap.data));
    return new Uint8Array(raw);
  }

  /** VK 原始 bytes → 不可匯出的 AES 金鑰（之後只用這個加解密） */
  function importVaultKey(vkRaw) {
    return subtle.importKey('raw', vkRaw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  // ============================================================
  // 資料加解密（用 VK）
  // ============================================================

  async function encryptJson(key, obj, aad) {
    const iv = randomBytes(IV_BYTES);
    const data = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(obj)));
    return { iv: toB64(iv), data: toB64(data) };
  }

  /** 金鑰錯誤、資料被竄改、AAD 不符都會丟出錯誤 */
  async function decryptJson(key, iv, data, aad) {
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv), additionalData: enc.encode(aad) }, key, fromB64(data));
    return JSON.parse(dec.decode(plain));
  }

  function aadFor(id, part) {
    return 'white-vault|' + id + '|' + part;
  }

  function encryptSummary(key, id, summary) { return encryptJson(key, summary, aadFor(id, 'summary')); }
  function decryptSummary(key, id, iv, data) { return decryptJson(key, iv, data, aadFor(id, 'summary')); }
  function encryptSecret(key, id, secret) { return encryptJson(key, secret, aadFor(id, 'secret')); }
  function decryptSecret(key, id, iv, data) { return decryptJson(key, iv, data, aadFor(id, 'secret')); }

  // ============================================================
  // 其他
  // ============================================================

  /** 產生強密碼：每一種有勾選的字元類型至少出現一次 */
  function generatePassword(length, opts) {
    opts = opts || {};
    const sets = [
      'ABCDEFGHJKLMNPQRSTUVWXYZ',   // 不含容易看錯的 I、O
      'abcdefghijkmnopqrstuvwxyz',  // 不含 l
      '23456789'                     // 不含 0、1
    ];
    if (opts.symbols !== false) sets.push('!@#$%^&*-_=+?');
    const all = sets.join('');
    length = Math.max(8, Math.min(64, length || 16));
    const out = sets.map(randomChar);
    while (out.length < length) out.push(randomChar(all));
    // Fisher–Yates 洗牌，讓必出現的字元位置也是隨機的
    for (let i = out.length - 1; i > 0; i--) {
      const limit = 256 - (256 % (i + 1));
      let x;
      do { x = randomBytes(1)[0]; } while (x >= limit);
      const j = x % (i + 1);
      const t = out[i]; out[i] = out[j]; out[j] = t;
    }
    return out.join('');
  }

  /** 主密碼強度（0～4），只是提示用 */
  function passwordStrength(pw) {
    pw = String(pw || '');
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 20;
    if (/[^\x00-\x7F]/.test(pw)) pool += 100;   // 中文等
    const bits = pw.length * Math.log2(Math.max(pool, 1));
    if (pw.length < 8 || bits < 36) return 0;
    if (bits < 50) return 1;
    if (bits < 65) return 2;
    if (bits < 80) return 3;
    return 4;
  }

  /**
   * 主密碼提示是否太明顯：提示裡直接包含主密碼、或主密碼裡有一大段就是提示，都不行
   * （比對時忽略大小寫、空白）
   */
  function hintRevealsPassword(hint, pw) {
    const norm = function (s) { return String(s || '').normalize('NFC').toLowerCase().replace(/\s+/g, ''); };
    const h = norm(hint), p = norm(pw);
    if (!h || !p) return false;
    if (h.indexOf(p) >= 0) return true;
    if (p.length >= 4 && h.length >= 4 && p.indexOf(h) >= 0 && h.length >= p.length * 0.6) return true;
    // 提示裡有連續一半以上的主密碼
    const half = Math.max(4, Math.ceil(p.length / 2));
    for (let i = 0; i + half <= p.length; i++) {
      if (h.indexOf(p.slice(i, i + half)) >= 0) return true;
    }
    return false;
  }

  const api = {
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    isSupported: isSupported,
    newSalt: newSalt,
    newId: newId,
    deriveMasterKeys: deriveMasterKeys,
    deriveRecoveryKeys: deriveRecoveryKeys,
    newRecoveryCode: newRecoveryCode,
    normalizeRecoveryCode: normalizeRecoveryCode,
    isValidRecoveryCode: isValidRecoveryCode,
    newVaultKeyRaw: newVaultKeyRaw,
    wipe: wipe,
    wrapVaultKey: wrapVaultKey,
    unwrapVaultKeyRaw: unwrapVaultKeyRaw,
    importVaultKey: importVaultKey,
    encryptSummary: encryptSummary,
    decryptSummary: decryptSummary,
    encryptSecret: encryptSecret,
    decryptSecret: decryptSecret,
    generatePassword: generatePassword,
    passwordStrength: passwordStrength,
    hintRevealsPassword: hintRevealsPassword
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.VaultCrypto = api;
})(typeof self !== 'undefined' ? self : globalThis);
