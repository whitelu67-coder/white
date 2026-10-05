// ============================================================
// White 密碼庫：加解密核心（只用瀏覽器內建的 Web Crypto，不引用任何加密套件）
// ------------------------------------------------------------
// 金鑰架構：
//   密碼庫金鑰 VK：建立時隨機產生的 AES-256 金鑰，帳號密碼都用它加密
//   主密碼 --PBKDF2-SHA256（600,000 次）＋ saltM--> 256 bits --HKDF-->
//       ・KEK：把 VK 加密包起來（wrapM）            → 只在手機上用
//       ・登入鑰 auth：送給 GAS 驗證（GAS 只存雜湊）→ 推不回主密碼，也推不出 KEK
//   → 換主密碼只要重新包 VK，不用重新加密所有資料
//
// 每一筆的帳號、密碼頭尾、完整密碼分開用 VK 加密（encryptPart）；名稱、分類…不加密（直接存在試算表）
// 每次加密都用新的隨機 IV；並把「這筆的 id」當作附加驗證資料（AAD），
// 避免有人把 A 筆的密文搬到 B 筆還能解得開。
// 瀏覽器、Node.js（測試用）都能載入。
// ============================================================
(function (root) {
  'use strict';

  const PBKDF2_ITERATIONS = 600000;            // 主密碼：OWASP 2023 建議 PBKDF2-SHA256 至少 600,000 次
  const SALT_BYTES = 16;
  const IV_BYTES = 12;                         // AES-GCM 建議的 IV 長度

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
  // 主密碼 → KEK（包 VK 用）＋ 登入鑰（給 GAS 驗證）
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

  /** 主密碼 → { kek, auth } */
  async function deriveMasterKeys(masterPassword, saltB64, iterations) {
    const base = await subtle.importKey('raw', enc.encode(String(masterPassword).normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'PBKDF2', salt: fromB64(saltB64), iterations: iterations || PBKDF2_ITERATIONS, hash: 'SHA-256' }, base, 256);
    return splitKeys(bits, 'master');
  }

  /** 登入鑰的雜湊：存在 GAS 的 VAULT_META，後端用一樣的算法比對（SHA-256(登入鑰字串) → base64） */
  async function authHash(authB64) {
    return toB64(new Uint8Array(await subtle.digest('SHA-256', enc.encode(authB64))));
  }

  // ============================================================
  // 密碼庫金鑰 VK：產生、包起來、打開
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
  // 帳號、密碼加解密（用 VK）
  // ============================================================

  /**
   * 分段加密：帳號（user）、密碼頭尾（mask）、完整密碼（pass）各自加密
   * 附加驗證資料是「id＋哪一段」，三段不能互換、也不能搬到別筆
   */
  async function encryptPart(key, id, part, text) {
    const iv = randomBytes(IV_BYTES);
    const data = await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode('white-vault|' + id + '|' + part) }, key, enc.encode(String(text || '')));
    return { iv: toB64(iv), data: toB64(data) };
  }

  async function decryptPart(key, id, part, iv, data) {
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv), additionalData: enc.encode('white-vault|' + id + '|' + part) }, key, fromB64(data));
    return dec.decode(plain);
  }

  // ============================================================
  // 主密碼工具用的檢查
  // ============================================================

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
    authHash: authHash,
    newVaultKeyRaw: newVaultKeyRaw,
    wipe: wipe,
    wrapVaultKey: wrapVaultKey,
    unwrapVaultKeyRaw: unwrapVaultKeyRaw,
    importVaultKey: importVaultKey,
    encryptPart: encryptPart,
    decryptPart: decryptPart,
    passwordStrength: passwordStrength,
    hintRevealsPassword: hintRevealsPassword
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.VaultCrypto = api;
})(typeof self !== 'undefined' ? self : globalThis);
