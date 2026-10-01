// ============================================================
// 主密碼工具：在自己電腦上產生新的 GAS 指令碼屬性 VAULT_META（更換主密碼）
// ------------------------------------------------------------
// ・全部在這台電腦的瀏覽器裡計算，不連網路、不送出任何東西
// ・用目前的主密碼打開密碼本金鑰，再用新的主密碼包起來（金鑰不變，帳密不用重新加密）
// ・沒有「建立」：密碼本已經建立好了；再建立一次會換掉金鑰，舊的帳密就打不開
// ・VAULT_META 裡沒有主密碼，只有：
//     saltM / iterations   推導用的參數
//     wrapM                用主密碼包起來的密碼本金鑰
//     authHashM            登入鑰的雜湊（後端用來確認主密碼對不對）
// ・沒有救援碼：忘記主密碼＝帳密救不回來。舊版 VAULT_META 裡的救援碼資料，換主密碼時會一起清掉
// ============================================================
(function (root) {
  'use strict';
  const VC = typeof module !== 'undefined' && module.exports ? require('../web/vault-crypto.js') : root.VaultCrypto;

  /** 主密碼只要求至少 8 個字（純數字、純英文都可以）；強度條只是參考，不會擋 */
  function checkNewMaster(pw, pw2, hint) {
    if (pw.length < 8) return '主密碼至少要 8 個字';
    if (pw !== pw2) return '兩次輸入的主密碼不一樣';
    if (hint && VC.hintRevealsPassword(hint, pw)) return '提示太明顯了（裡面有主密碼的內容），請換一個只有家人懂的提示';
    return '';
  }

  function parseMeta(text) {
    let m;
    try { m = JSON.parse(String(text || '').trim()); } catch (e) { m = null; }
    if (!m || !m.saltM || !m.wrapM || !m.iterations) throw new Error('目前的 VAULT_META 格式不對，請從 GAS 指令碼屬性整段複製過來');
    return m;
  }

  async function build(pw, raw) {
    const saltM = VC.newSalt();
    const m = await VC.deriveMasterKeys(pw, saltM, VC.PBKDF2_ITERATIONS);
    return JSON.stringify({ v: 3, saltM: saltM, iterations: VC.PBKDF2_ITERATIONS, wrapM: await VC.wrapVaultKey(m.kek, raw), authHashM: await VC.authHash(m.auth) });
  }

  /** 更換主密碼：用目前的主密碼打開金鑰，再用新的主密碼包起來 */
  async function changeMaster(metaText, oldPw, newPw) {
    const meta = parseMeta(metaText);
    const m = await VC.deriveMasterKeys(oldPw, meta.saltM, meta.iterations);
    let raw;
    try { raw = await VC.unwrapVaultKeyRaw(m.kek, meta.wrapM); } catch (e) { throw new Error('目前的主密碼錯誤'); }
    try { return { meta: await build(newPw, raw), removedRecovery: !!meta.wrapR }; } finally { VC.wipe(raw); }
  }

  const api = { checkNewMaster: checkNewMaster, changeMaster: changeMaster };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.MasterTool = api;
})(typeof self !== 'undefined' ? self : globalThis);
