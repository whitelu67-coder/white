// ============================================================
// White 密碼本：LIFF 網頁
// ------------------------------------------------------------
// 流程：LINE 身分（ID Token）→ 輸入主密碼 → 手機推導出「登入鑰」給後端驗證、「KEK」留在手機
//      → 後端驗證通過才給「包起來的密碼本金鑰」和摘要 → 手機用 KEK 打開金鑰、解密
// 安全原則：
//   ・主密碼、金鑰、明文只在這個網頁的記憶體裡，不存 localStorage、不寫 console
//   ・解鎖只解開「摘要」；帳號密碼點開那一筆才下載、才解密，關掉就清掉
//   ・畫面一律用 textContent 放資料，不用 innerHTML，資料裡就算有 HTML 也不會被執行
//   ・5 分鐘沒動作、或切到別的 App，就清掉金鑰鎖定
// ============================================================
(function () {
  'use strict';

  const CFG = window.VAULT_CONFIG || {};
  const VC = window.VaultCrypto;
  // 本機預覽（localhost 或直接開檔案）才會用假的 LINE 身分；正式網址是 https，不會符合
  const IS_LOCAL = /^(localhost|127\.0\.0\.1)$/.test(location.hostname) || location.protocol === 'file:';
  const CATEGORIES = [
    { key: 'home', label: '🏠 家庭' },
    { key: 'school', label: '🏫 學校' },
    { key: 'finance', label: '💰 金融' },
    { key: 'shopping', label: '🛒 購物' },
    { key: 'work', label: '💼 工作' },
    { key: 'other', label: '📦 其他' }
  ];
  const ACTION_LABELS = { open: '輸入主密碼打開', init: '建立密碼本', view: '查看帳密', create: '新增', update: '修改',
    delete: '刪除', viewAll: '取出全部（匯出備份）', rekey: '更換主密碼', restore: '從備份還原', recover: '使用救援碼',
    newRecovery: '重新產生救援碼', hint: '修改提示', lock: '緊急鎖定', wrongPassword: '⚠️ 主密碼錯誤', wrongRecovery: '⚠️ 救援碼錯誤' };

  const state = {
    idToken: null,
    meta: null,        // { initialized, saltM, iterations, saltR, hint }
    session: null,     // 後端發的工作階段（15 分鐘）
    wrapM: null,       // 用主密碼包起來的密碼本金鑰（沒有主密碼打不開）
    vk: null,          // 密碼本金鑰（CryptoKey，不可匯出）
    encrypted: null,   // 還沒解開的摘要
    items: [],         // [{ id, rev, updatedAt, updatedBy, s: 摘要明文 }]
    pending: null,     // 顯示救援碼畫面時，接下來要做的事
    recoverRaw: null,  // 用救援碼打開後、設定新主密碼前的密碼本金鑰（用完馬上清掉）
    filterCat: '',
    detail: null,
    editing: null,
    lockTimer: null,
    revealTimer: null,
    busy: false
  };

  const $ = function (id) { return document.getElementById(id); };

  // ============================================================
  // 小工具
  // ============================================================

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  const SCREENS = ['screen-loading', 'screen-message', 'screen-setup', 'screen-recovery-code', 'screen-unlock', 'screen-recover', 'screen-newmaster', 'screen-list'];
  function show(screenId) {
    SCREENS.forEach(function (id) { $(id).hidden = id !== screenId; });
  }

  function showMessage(icon, title, text, opts) {
    opts = opts || {};
    $('message-icon').textContent = icon;
    $('message-title').textContent = title;
    $('message-text').textContent = text || '';
    $('message-retry').hidden = !opts.retry;
    $('message-relogin').hidden = !opts.relogin;
    show('screen-message');
  }

  function showLocked(lock) {
    clearSecrets();
    showMessage('🔒', '密碼本已被緊急鎖定',
      (lock && lock.at ? fmtTime(lock.at) + '　' : '') + (lock && lock.by ? '原因：' + lock.by + '\n\n' : '\n') +
      '所有人都暫時打不開，資料不會刪除。\n確認安全後，到密碼本的 GAS 刪除指令碼屬性 VAULT_LOCKED（或執行 unlockVault）即可解除。', { retry: true });
  }

  function setError(id, text) {
    const e = $(id);
    e.textContent = text || '';
    e.hidden = !text;
  }

  let toastTimer = null;
  function toast(text) {
    const t = $('toast');
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 2400);
  }

  function openSheet(id) { $(id).hidden = false; }
  function closeSheet(id) {
    $(id).hidden = true;
    if (id === 'sheet-detail') clearDetail();
    if (id === 'sheet-edit') clearEdit();
  }

  function catLabel(key) {
    const c = CATEGORIES.filter(function (x) { return x.key === key; })[0];
    return c ? c.label : '📦 其他';
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return '';
    const p = function (n) { return ('0' + n).slice(-2); };
    return d.getFullYear() + '/' + p(d.getMonth() + 1) + '/' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      // 有些 App 內建瀏覽器不支援 Clipboard API
      const ta = el('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      ta.value = '';
    }
    toast('已複製');
  }

  function renderStrength(barId, pw) {
    $(barId).className = pw ? 's' + VC.passwordStrength(pw) : '';
  }

  /** 新主密碼的共同檢查（建立、換主密碼、用救援碼重設） */
  function checkNewMaster(pw, pw2, hint) {
    if (pw.length < 8) return '主密碼至少要 8 個字';
    if (VC.passwordStrength(pw) < 2) return '主密碼太容易被猜到，請加長或混合中英文、數字、符號';
    if (pw !== pw2) return '兩次輸入的主密碼不一樣';
    if (hint && VC.hintRevealsPassword(hint, pw)) return '提示太明顯了（裡面有主密碼的內容），請換一個只有家人懂的提示';
    return '';
  }

  // ============================================================
  // 後端 API
  // ============================================================

  async function api(action, data) {
    const body = Object.assign({ action: action, idToken: state.idToken, session: state.session }, data || {});
    let res;
    if (window.__VAULT_MOCK_API__) {
      res = await window.__VAULT_MOCK_API__(body);
    } else {
      // 不加 Content-Type（預設 text/plain）：跨網域時才不會觸發預檢請求（GAS 不支援 OPTIONS）
      const r = await fetch(CFG.API_URL, { method: 'POST', body: JSON.stringify(body), redirect: 'follow', credentials: 'omit' });
      res = await r.json();
    }
    if (!res.ok) {
      const err = new Error(res.error || '發生錯誤');
      err.code = res.code;
      err.res = res;
      if (res.code === 'LOCKED') { showLocked(res.lock); err.handled = true; }
      else if (res.code === 'UNAUTHORIZED' || res.code === 'REAUTH') {
        clearSecrets();
        showMessage('🔑', '需要重新登入 LINE', res.error, { relogin: true });
        err.handled = true;
      } else if (res.code === 'SESSION') { lock('工作階段已過期，請重新輸入主密碼'); err.handled = true; }
      throw err;
    }
    return res;
  }

  function relogin() {
    if (IS_LOCAL) { location.reload(); return; }
    liff.logout();
    liff.login({ redirectUri: location.href });
  }

  // ============================================================
  // 啟動
  // ============================================================

  async function boot() {
    if (!window.isSecureContext || !VC || !VC.isSupported()) {
      showMessage('⚠️', '無法使用', '這個瀏覽器不支援加密功能，請用手機 LINE 開啟。');
      return;
    }
    if (IS_LOCAL && CFG.DEV_MOCK) await loadScript('dev-mock.js');
    if (!CFG.LIFF_ID || (!CFG.API_URL && !window.__VAULT_MOCK_API__)) {
      showMessage('🛠️', '還沒設定完成', '請在 config.js 填入 LIFF_ID 和 API_URL。');
      return;
    }
    try {
      await liff.init({ liffId: CFG.LIFF_ID });
      if (!liff.isLoggedIn()) {
        liff.login({ redirectUri: location.href });
        return;
      }
      state.idToken = liff.getIDToken();
      if (!state.idToken) {
        showMessage('⚠️', '取得身分失敗', 'LIFF 需要開啟 openid 權限，請檢查 LINE Developers 的 LIFF 設定。');
        return;
      }
      $('loading-text').textContent = '正在讀取密碼本…';
      await loadMeta();
    } catch (e) {
      if (e.handled) return;
      if (e.code === 'FORBIDDEN') showMessage('🚫', '你沒有權限', '這個密碼本只開放給家人使用。');
      else showMessage('😥', '讀取失敗', e.message || '請稍後再試一次。', { retry: true });
    }
  }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      const s = document.createElement('script');
      s.src = src;
      s.onload = resolve;
      s.onerror = reject;
      document.body.appendChild(s);
    });
  }

  /** 還沒輸入主密碼：只拿得到 salt、提示、有沒有被鎖定 */
  async function loadMeta() {
    const res = await api('getMeta');
    if (res.lock) return showLocked(res.lock);
    state.meta = res.meta;
    if (!res.meta.initialized) {
      show('screen-setup');
      $('setup-pw').focus();
      return;
    }
    showUnlock(res.cooldown ? '錯太多次了，請 ' + Math.ceil(res.cooldown / 60) + ' 分鐘後再試' : '');
  }

  function showUnlock(errorText) {
    $('unlock-hint-btn').hidden = !(state.meta && state.meta.hint);
    $('unlock-hint').hidden = true;
    $('unlock-hint').textContent = state.meta && state.meta.hint ? '💡 ' + state.meta.hint : '';
    setError('unlock-error', errorText || '');
    show('screen-unlock');
    $('unlock-pw').focus();
  }

  // ============================================================
  // 建立密碼本：主密碼 → 救援碼 → 完成
  // ============================================================

  function onSetup() {
    const pw = $('setup-pw').value, pw2 = $('setup-pw2').value, hint = $('setup-hint').value.trim();
    const err = checkNewMaster(pw, pw2, hint);
    if (err) return setError('setup-error', err);
    setError('setup-error', '');
    showRecoveryCode({ mode: 'setup', pw: pw, hint: hint });
  }

  function showRecoveryCode(pending) {
    pending.code = VC.newRecoveryCode();
    state.pending = pending;
    $('rc-code').textContent = pending.code;
    $('rc-agree').checked = false;
    setError('rc-error', '');
    show('screen-recovery-code');
  }

  /** 救援碼抄好之後：真正建立／重設 */
  async function onRecoveryCodeDone() {
    if (!$('rc-agree').checked) return setError('rc-error', '請先把救援碼抄在紙上，再勾選確認');
    const p = state.pending;
    if (!p) return;
    await withBusy('rc-done', '處理中…', async function () {
      try {
        if (p.mode === 'setup') await finishSetup(p);
        else if (p.mode === 'recover') await finishRecover(p);
        else if (p.mode === 'regen') await finishRegen(p);
        state.pending = null;
        $('rc-code').textContent = '';
      } catch (e) {
        if (!e.handled) setError('rc-error', e.message || '發生錯誤');
      }
    });
  }

  async function finishSetup(p) {
    const saltM = VC.newSalt(), saltR = VC.newSalt();
    const m = await VC.deriveMasterKeys(p.pw, saltM, VC.PBKDF2_ITERATIONS);
    const r = await VC.deriveRecoveryKeys(p.code, saltR);
    const raw = VC.newVaultKeyRaw();
    const wrapM = await VC.wrapVaultKey(m.kek, raw);
    const wrapR = await VC.wrapVaultKey(r.kek, raw);
    const res = await api('initVault', { saltM: saltM, iterations: VC.PBKDF2_ITERATIONS, wrapM: wrapM, authM: m.auth,
      saltR: saltR, wrapR: wrapR, authR: r.auth, hint: p.hint });
    state.vk = await VC.importVaultKey(raw);
    VC.wipe(raw);
    state.session = res.session;
    state.wrapM = wrapM;
    state.meta = { initialized: true, saltM: saltM, iterations: VC.PBKDF2_ITERATIONS, saltR: saltR, hint: p.hint };
    ['setup-pw', 'setup-pw2', 'setup-hint'].forEach(function (id) { $(id).value = ''; });
    state.items = [];
    renderList();
    resetLockTimer();
    toast('密碼本建立完成');
  }

  // ============================================================
  // 解鎖、鎖定
  // ============================================================

  async function onUnlock(ev) {
    ev.preventDefault();
    const pw = $('unlock-pw').value;
    if (!pw) return;
    setError('unlock-error', '');
    await withBusy('unlock-submit', '解鎖中…', async function () {
      const m = await VC.deriveMasterKeys(pw, state.meta.saltM, state.meta.iterations);
      let res;
      try {
        res = await api('unlock', { auth: m.auth });
      } catch (e) {
        if (!e.handled) { setError('unlock-error', e.message); $('unlock-pw').select(); }
        return;
      }
      const raw = await VC.unwrapVaultKeyRaw(m.kek, res.wrapM);
      state.vk = await VC.importVaultKey(raw);
      VC.wipe(raw);
      state.session = res.session;
      state.wrapM = res.wrapM;
      $('unlock-pw').value = '';
      state.encrypted = res.entries;
      await decryptIndex();
      renderList();
      resetLockTimer();
    });
  }

  /** 解開全部摘要（名稱、分類、小分類、網址、備註） */
  async function decryptIndex() {
    const out = [];
    let broken = 0;
    for (const e of state.encrypted || []) {
      try {
        const s = await VC.decryptSummary(state.vk, e.id, e.summary.iv, e.summary.data);
        out.push({ id: e.id, rev: e.rev, updatedAt: e.updatedAt, updatedBy: e.updatedBy, s: s });
      } catch (err) {
        broken++;
      }
    }
    state.items = out;
    state.encrypted = null;
    if (broken) toast('有 ' + broken + ' 筆資料解不開（可能已損毀）');
  }

  async function reloadIndex() {
    const res = await api('getIndex');
    state.encrypted = res.entries;
    await decryptIndex();
    renderList();
  }

  /** 清掉所有機密（金鑰、工作階段、解開的資料、畫面上的欄位） */
  function clearSecrets() {
    if (state.session) api('logout').catch(function () {});
    state.vk = null;
    state.session = null;
    state.wrapM = null;
    state.items = [];
    state.encrypted = null;
    state.pending = null;
    if (state.recoverRaw) { VC.wipe(state.recoverRaw); state.recoverRaw = null; }
    ['sheet-detail', 'sheet-edit', 'sheet-settings'].forEach(closeSheet);
    ['s-old', 's-new', 's-new2', 's-new-hint', 's-hint', 's-hint-pw', 's-rc-pw', 'search', 'unlock-pw', 'rec-code', 'nm-pw', 'nm-pw2'].forEach(function (id) { $(id).value = ''; });
    $('rc-code').textContent = '';
    $('list').textContent = '';
    clearTimeout(state.lockTimer);
  }

  function lock(reason) {
    const wasOpen = !!(state.vk || state.recoverRaw || state.pending);
    if (state.pending && state.pending.raw) VC.wipe(state.pending.raw);
    clearSecrets();
    if (!wasOpen && !reason) return;
    // 還在第一次建立的途中（密碼本還不存在）：回到建立畫面重新開始
    if (!state.meta || !state.meta.initialized) {
      ['setup-pw', 'setup-pw2', 'setup-hint'].forEach(function (id) { $(id).value = ''; });
      setError('setup-error', reason ? reason + '，請重新設定' : '');
      show('screen-setup');
      return;
    }
    showUnlock(reason || '');
  }

  function resetLockTimer() {
    clearTimeout(state.lockTimer);
    if (state.vk || state.recoverRaw) state.lockTimer = setTimeout(function () { lock('已經 5 分鐘沒有動作，自動鎖定了'); }, CFG.AUTO_LOCK_MS || 300000);
  }

  // ============================================================
  // 忘記主密碼：救援碼 → 設定新主密碼 → 新的救援碼
  // ============================================================

  async function onRecover() {
    const code = $('rec-code').value;
    if (!VC.isValidRecoveryCode(code)) return setError('rec-error', '救援碼格式不對（應該是 30 個字）');
    setError('rec-error', '');
    await withBusy('rec-submit', '確認中…', async function () {
      const r = await VC.deriveRecoveryKeys(code, state.meta.saltR);
      let res;
      try {
        res = await api('recover', { auth: r.auth });
      } catch (e) {
        if (!e.handled) setError('rec-error', e.message);
        return;
      }
      state.recoverRaw = await VC.unwrapVaultKeyRaw(r.kek, res.wrapR);
      state.session = res.session;
      $('rec-code').value = '';
      ['nm-pw', 'nm-pw2', 'nm-hint'].forEach(function (id) { $(id).value = ''; });
      setError('nm-error', '');
      show('screen-newmaster');
      resetLockTimer();
    });
  }

  function onNewMaster() {
    const pw = $('nm-pw').value, pw2 = $('nm-pw2').value, hint = $('nm-hint').value.trim();
    const err = checkNewMaster(pw, pw2, hint);
    if (err) return setError('nm-error', err);
    setError('nm-error', '');
    showRecoveryCode({ mode: 'recover', pw: pw, hint: hint });
  }

  async function finishRecover(p) {
    const saltM = VC.newSalt(), saltR = VC.newSalt();
    const m = await VC.deriveMasterKeys(p.pw, saltM, VC.PBKDF2_ITERATIONS);
    const r = await VC.deriveRecoveryKeys(p.code, saltR);
    const wrapM = await VC.wrapVaultKey(m.kek, state.recoverRaw);
    const res = await api('changeMaster', { saltM: saltM, iterations: VC.PBKDF2_ITERATIONS, wrapM: wrapM, authM: m.auth,
      saltR: saltR, wrapR: await VC.wrapVaultKey(r.kek, state.recoverRaw), authR: r.auth, hint: p.hint });
    state.vk = await VC.importVaultKey(state.recoverRaw);
    VC.wipe(state.recoverRaw);
    state.recoverRaw = null;
    state.session = res.session;
    state.wrapM = wrapM;
    state.meta = Object.assign({}, state.meta, { saltM: saltM, iterations: VC.PBKDF2_ITERATIONS, saltR: saltR, hint: p.hint });
    ['nm-pw', 'nm-pw2', 'nm-hint'].forEach(function (id) { $(id).value = ''; });
    await reloadIndex();
    resetLockTimer();
    alert('新的主密碼設定好了。\n\n請告訴家人新的主密碼，舊的救援碼已經作廢，請保存剛剛抄下的新救援碼。');
  }

  // ============================================================
  // 清單
  // ============================================================

  function renderChips() {
    const box = $('chips');
    box.textContent = '';
    [{ key: '', label: '全部' }].concat(CATEGORIES).forEach(function (c) {
      const b = el('button', 'chip' + (state.filterCat === c.key ? ' on' : ''), c.label);
      b.type = 'button';
      b.addEventListener('click', function () { state.filterCat = c.key; renderList(); });
      box.appendChild(b);
    });
  }

  function matches(item, q) {
    if (state.filterCat && item.s.category !== state.filterCat) return false;
    if (!q) return true;
    const hay = [item.s.name, item.s.subcategory, item.s.url, item.s.note, catLabel(item.s.category)].join(' ').toLowerCase();
    return q.toLowerCase().split(/\s+/).filter(Boolean).every(function (w) { return hay.indexOf(w) >= 0; });
  }

  function renderList() {
    show('screen-list');
    renderChips();
    const q = $('search').value.trim();
    const list = $('list');
    list.textContent = '';
    const shown = state.items.filter(function (it) { return matches(it, q); });
    if (!shown.length) {
      list.appendChild(el('div', 'empty', state.items.length ? '找不到符合的項目' : '還沒有任何資料，按下面的「＋ 新增」開始'));
      return;
    }
    // 分類 → 小分類 → 名稱
    CATEGORIES.forEach(function (c) {
      const inCat = shown.filter(function (it) { return (it.s.category || 'other') === c.key; });
      if (!inCat.length) return;
      const g = el('div', 'group');
      g.appendChild(el('div', 'group-title', c.label + '（' + inCat.length + '）'));
      const subs = {};
      inCat.forEach(function (it) { const k = it.s.subcategory || ''; (subs[k] = subs[k] || []).push(it); });
      Object.keys(subs).sort(function (a, b) { return (a === '') - (b === '') || a.localeCompare(b, 'zh-Hant'); }).forEach(function (sub) {
        if (sub) g.appendChild(el('div', 'sub-title', '› ' + sub));
        subs[sub].sort(function (a, b) { return a.s.name.localeCompare(b.s.name, 'zh-Hant'); }).forEach(function (it) {
          const b = el('button', 'item');
          b.type = 'button';
          const left = el('div');
          left.style.minWidth = '0';
          left.appendChild(el('div', 'item-name', it.s.name));
          const extra = [it.s.url ? it.s.url.replace(/^https?:\/\//, '') : '', it.s.note].filter(Boolean).join('・');
          if (extra) left.appendChild(el('div', 'item-sub', extra));
          b.appendChild(left);
          b.appendChild(el('span', 'item-arrow', '›'));
          b.addEventListener('click', function () { openDetail(it); });
          g.appendChild(b);
        });
      });
      list.appendChild(g);
    });
  }

  // ============================================================
  // 詳細資料：點開才下載並解密帳號密碼
  // ============================================================

  async function openDetail(item) {
    clearDetail();
    state.detail = { item: item, secret: null };
    $('d-name').textContent = item.s.name;
    $('d-cat').textContent = catLabel(item.s.category) + (item.s.subcategory ? ' › ' + item.s.subcategory : '');
    $('d-user').textContent = '解密中…';
    $('d-pass').textContent = '••••••••';
    $('d-url-row').hidden = !item.s.url;
    $('d-url').textContent = item.s.url || '';
    $('d-url').href = /^https?:\/\//i.test(item.s.url || '') ? item.s.url : '#';
    $('d-note-row').hidden = !item.s.note;
    $('d-note').textContent = item.s.note || '';
    $('d-meta').textContent = '最後修改：' + (item.updatedBy || '') + ' ' + fmtTime(item.updatedAt);
    openSheet('sheet-detail');
    try {
      const res = await api('getSecret', { id: item.id });
      if (!state.detail || state.detail.item !== item) return;   // 等待中已經關掉了
      item.rev = res.rev;
      state.detail.secret = await VC.decryptSecret(state.vk, item.id, res.secret.iv, res.secret.data);
      $('d-user').textContent = state.detail.secret.username || '（沒有帳號）';
    } catch (e) {
      if (!e.handled) $('d-user').textContent = '讀取失敗：' + (e.message || '');
    }
  }

  function clearDetail() {
    clearTimeout(state.revealTimer);
    state.detail = null;
    $('d-user').textContent = '';
    $('d-pass').textContent = '••••••••';
  }

  function toggleReveal() {
    if (!state.detail || !state.detail.secret) return;
    const span = $('d-pass');
    clearTimeout(state.revealTimer);
    if (span.textContent === '••••••••') {
      span.textContent = state.detail.secret.password || '（沒有密碼）';
      state.revealTimer = setTimeout(function () { span.textContent = '••••••••'; }, CFG.REVEAL_MS || 30000);
    } else {
      span.textContent = '••••••••';
    }
  }

  async function onDelete() {
    const d = state.detail;
    if (!d) return;
    if (!confirm('確定要刪除「' + d.item.s.name + '」嗎？刪除後無法復原。')) return;
    try {
      await api('deleteEntry', { id: d.item.id, rev: d.item.rev });
      state.items = state.items.filter(function (x) { return x.id !== d.item.id; });
      closeSheet('sheet-detail');
      renderList();
      toast('已刪除');
    } catch (e) {
      handleSaveError(e);
    }
  }

  // ============================================================
  // 新增、修改
  // ============================================================

  function fillCategorySelect() {
    const sel = $('e-cat');
    sel.textContent = '';
    CATEGORIES.forEach(function (c) {
      const o = el('option', null, c.label);
      o.value = c.key;
      sel.appendChild(o);
    });
  }

  /** 小分類：建議同一個分類裡用過的（避免「台新」「台新銀行」各打一種） */
  function fillSubSuggestions() {
    const cat = $('e-cat').value;
    const dl = $('e-sub-list');
    dl.textContent = '';
    const seen = {};
    state.items.forEach(function (it) {
      const s = it.s.subcategory;
      if (s && it.s.category === cat && !seen[s]) { seen[s] = 1; const o = el('option'); o.value = s; dl.appendChild(o); }
    });
  }

  function openEdit(item, secret) {
    state.editing = item ? { item: item } : null;
    $('e-title').textContent = item ? '✏️ 修改' : '＋ 新增';
    $('e-name').value = item ? item.s.name : '';
    $('e-cat').value = item ? (item.s.category || 'other') : (state.filterCat || 'finance');
    $('e-sub').value = item ? (item.s.subcategory || '') : '';
    $('e-url').value = item ? (item.s.url || '') : '';
    $('e-note').value = item ? (item.s.note || '') : '';
    $('e-user').value = secret ? (secret.username || '') : '';
    $('e-pass').value = secret ? (secret.password || '') : '';
    $('e-pass').type = 'password';
    setError('e-error', '');
    fillSubSuggestions();
    closeSheet('sheet-detail');
    state.editing = item ? { item: item } : null;
    openSheet('sheet-edit');
    $('e-name').focus();
  }

  function clearEdit() {
    state.editing = null;
    ['e-name', 'e-sub', 'e-url', 'e-note', 'e-user', 'e-pass'].forEach(function (id) { $(id).value = ''; });
  }

  async function onSave() {
    const summary = {
      name: $('e-name').value.trim(),
      category: $('e-cat').value,
      subcategory: $('e-sub').value.trim(),
      url: $('e-url').value.trim(),
      note: $('e-note').value.trim()
    };
    const secret = { username: $('e-user').value, password: $('e-pass').value };
    if (!summary.name) return setError('e-error', '請輸入名稱');
    if (summary.url && !/^https?:\/\//i.test(summary.url)) return setError('e-error', '網址要用 http:// 或 https:// 開頭');
    setError('e-error', '');
    const item = state.editing && state.editing.item;
    const id = item ? item.id : VC.newId();
    await withBusy('e-save', '儲存中…', async function () {
      try {
        const res = await api('saveEntry', {
          id: id,
          rev: item ? item.rev : 0,
          summary: await VC.encryptSummary(state.vk, id, summary),
          secret: await VC.encryptSecret(state.vk, id, secret)
        });
        const saved = { id: id, rev: res.rev, updatedAt: res.updatedAt, updatedBy: res.updatedBy, s: summary };
        state.items = state.items.filter(function (x) { return x.id !== id; }).concat([saved]);
        closeSheet('sheet-edit');
        renderList();
        toast(item ? '已修改' : '已新增');
      } catch (e) {
        handleSaveError(e);
      }
    });
  }

  function handleSaveError(e) {
    if (e.handled) return;
    if (e.code === 'CONFLICT' || e.code === 'NOT_FOUND') {
      alert(e.message + '\n\n會重新讀取最新的資料。');
      ['sheet-detail', 'sheet-edit'].forEach(closeSheet);
      reloadIndex().catch(function (err) { if (!err.handled) toast(err.message); });
    } else {
      toast(e.message || '儲存失敗');
    }
  }

  // ============================================================
  // 設定
  // ============================================================

  /** 用主密碼打開「包起來的密碼本金鑰」→ 原始 bytes（打錯會丟出錯誤），同時回傳登入鑰 */
  async function openWithMaster(pw) {
    const m = await VC.deriveMasterKeys(pw, state.meta.saltM, state.meta.iterations);
    try {
      return { raw: await VC.unwrapVaultKeyRaw(m.kek, state.wrapM), auth: m.auth };
    } catch (e) {
      throw new Error('主密碼錯誤');
    }
  }

  async function onRekey() {
    const oldPw = $('s-old').value, pw = $('s-new').value, pw2 = $('s-new2').value, hint = $('s-new-hint').value.trim();
    const err = checkNewMaster(pw, pw2, hint);
    if (err) return setError('s-error', err);
    if (!hint && state.meta.hint && VC.hintRevealsPassword(state.meta.hint, pw)) return setError('s-error', '目前的提示會洩漏新的主密碼，請一起輸入新的提示');
    setError('s-error', '');
    await withBusy('s-rekey', '更換中…', async function () {
      let old;
      try { old = await openWithMaster(oldPw); } catch (e) { return setError('s-error', '目前的主密碼錯誤'); }
      try {
        const saltM = VC.newSalt();
        const m = await VC.deriveMasterKeys(pw, saltM, VC.PBKDF2_ITERATIONS);
        const wrapM = await VC.wrapVaultKey(m.kek, old.raw);
        const body = { authOld: old.auth, saltM: saltM, iterations: VC.PBKDF2_ITERATIONS, wrapM: wrapM, authM: m.auth };
        if (hint) body.hint = hint;
        const res = await api('changeMaster', body);
        state.session = res.session;
        state.wrapM = wrapM;
        state.meta = Object.assign({}, state.meta, { saltM: saltM, iterations: VC.PBKDF2_ITERATIONS }, hint ? { hint: hint } : {});
        ['s-old', 's-new', 's-new2', 's-new-hint'].forEach(function (id) { $(id).value = ''; });
        renderStrength('s-strength-bar', '');
        closeSheet('sheet-settings');
        alert('主密碼已更換。\n\n請記得告訴家人新的主密碼，他們下次打開要用新的。');
      } catch (e) {
        if (!e.handled) setError('s-error', e.message);
      } finally {
        VC.wipe(old.raw);
      }
    });
  }

  async function onSaveHint() {
    const hint = $('s-hint').value.trim(), pw = $('s-hint-pw').value;
    setError('s-hint-error', '');
    await withBusy('s-hint-save', '儲存中…', async function () {
      let old;
      try { old = await openWithMaster(pw); } catch (e) { return setError('s-hint-error', '主密碼錯誤'); }
      VC.wipe(old.raw);
      if (hint && VC.hintRevealsPassword(hint, pw)) return setError('s-hint-error', '提示太明顯了（裡面有主密碼的內容）');
      try {
        await api('setHint', { hint: hint });
        state.meta.hint = hint;
        $('s-hint').value = $('s-hint-pw').value = '';
        $('s-hint-now').textContent = hint ? '目前的提示：' + hint : '目前沒有設定提示';
        toast('提示已更新');
      } catch (e) {
        if (!e.handled) setError('s-hint-error', e.message);
      }
    });
  }

  async function onRegenRecovery() {
    const pw = $('s-rc-pw').value;
    setError('s-rc-error', '');
    await withBusy('s-rc-new', '確認中…', async function () {
      let old;
      try { old = await openWithMaster(pw); } catch (e) { return setError('s-rc-error', '主密碼錯誤'); }
      $('s-rc-pw').value = '';
      closeSheet('sheet-settings');
      showRecoveryCode({ mode: 'regen', raw: old.raw, authOld: old.auth });
    });
  }

  async function finishRegen(p) {
    try {
      const saltR = VC.newSalt();
      const r = await VC.deriveRecoveryKeys(p.code, saltR);
      await api('setRecovery', { authOld: p.authOld, saltR: saltR, wrapR: await VC.wrapVaultKey(r.kek, p.raw), authR: r.auth });
      state.meta.saltR = saltR;
      renderList();
      toast('新的救援碼已生效，舊的已作廢');
    } finally {
      VC.wipe(p.raw);
    }
  }

  async function onExport() {
    await withBusy('s-export', '準備中…', async function () {
      try {
        const res = await api('getAllSecrets');
        for (const e of res.entries) {   // 先確認每一筆都解得開，才匯出
          await VC.decryptSummary(state.vk, e.id, e.summary.iv, e.summary.data);
          await VC.decryptSecret(state.vk, e.id, e.secret.iv, e.secret.data);
        }
        const backup = { format: 'white-vault-backup', version: 2, exportedAt: new Date().toISOString(),
          saltM: res.saltM, iterations: res.iterations, wrapM: res.wrapM, entries: res.entries };
        const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' });
        const a = el('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'white-vault-backup-' + new Date().toISOString().slice(0, 10) + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
        $('s-backup-msg').textContent = '✅ 已匯出 ' + backup.entries.length + ' 筆（檔案是加密的，要用現在的主密碼才能還原）。如果在 LINE 裡沒有出現下載，請用「用預設瀏覽器開啟」再匯出一次。';
      } catch (e) {
        if (!e.handled) $('s-backup-msg').textContent = '❌ ' + e.message;
      }
    });
  }

  async function onImport(ev) {
    const file = ev.target.files[0];
    ev.target.value = '';
    if (!file) return;
    let backup;
    try {
      backup = JSON.parse(await file.text());
      if (backup.format !== 'white-vault-backup' || backup.version !== 2 || !backup.wrapM || !Array.isArray(backup.entries)) throw new Error();
    } catch (e) {
      $('s-backup-msg').textContent = '❌ 這不是密碼本的備份檔';
      return;
    }
    const pw = prompt('請輸入「備份當時」的主密碼（' + backup.entries.length + ' 筆，備份時間 ' + fmtTime(backup.exportedAt) + '）');
    if (!pw) return;
    let bk;
    try {
      const m = await VC.deriveMasterKeys(pw, backup.saltM, backup.iterations);
      const raw = await VC.unwrapVaultKeyRaw(m.kek, backup.wrapM);
      bk = await VC.importVaultKey(raw);
      VC.wipe(raw);
    } catch (e) {
      $('s-backup-msg').textContent = '❌ 主密碼錯誤，無法還原';
      return;
    }
    // 用備份的金鑰解開、再用現在的金鑰重新加密（主密碼、救援碼維持現在的）
    const entries = [];
    try {
      for (const e of backup.entries) {
        const s = await VC.decryptSummary(bk, e.id, e.summary.iv, e.summary.data);
        const x = await VC.decryptSecret(bk, e.id, e.secret.iv, e.secret.data);
        entries.push({ id: e.id, summary: await VC.encryptSummary(state.vk, e.id, s), secret: await VC.encryptSecret(state.vk, e.id, x) });
      }
    } catch (e) {
      $('s-backup-msg').textContent = '❌ 備份檔有資料損毀，無法還原';
      return;
    }
    if (!confirm('確定要還原嗎？\n\n目前密碼本的「全部」資料會被備份檔的 ' + entries.length + ' 筆取代（主密碼、救援碼不變）。家人會收到通知。')) return;
    try {
      await api('restore', { entries: entries });
      closeSheet('sheet-settings');
      await reloadIndex();
      toast('已從備份還原 ' + entries.length + ' 筆');
    } catch (e) {
      if (!e.handled) $('s-backup-msg').textContent = '❌ ' + e.message;
    }
  }

  async function onLoadLog() {
    await withBusy('s-log-load', '讀取中…', async function () {
      const res = await api('getLog');
      const names = {};
      state.items.forEach(function (it) { names[it.id] = it.s.name; });
      const ul = $('s-log');
      ul.textContent = '';
      if (!res.log.length) ul.appendChild(el('li', null, '還沒有紀錄'));
      res.log.forEach(function (l) {
        const what = (ACTION_LABELS[l.action] || l.action) + (l.entryId ? '「' + (names[l.entryId] || '已刪除的項目') + '」' : '');
        ul.appendChild(el('li', /^wrong/.test(l.action) ? 'warn-line' : null, fmtTime(l.time) + '　' + l.name + '　' + what));
      });
    });
  }

  async function onEmergencyLock() {
    if (!confirm('確定要緊急鎖定嗎？\n\n所有人都會打不開密碼本，要到 GAS 刪除 VAULT_LOCKED 才能解除。家人會收到通知。')) return;
    try {
      const res = await api('lockVault');
      showLocked(res.lock);
    } catch (e) {
      if (!e.handled) toast(e.message);
    }
  }

  function openSettings() {
    ['s-error', 's-hint-error', 's-rc-error'].forEach(function (id) { setError(id, ''); });
    $('s-backup-msg').textContent = '';
    $('s-log').textContent = '';
    $('s-hint-now').textContent = state.meta.hint ? '目前的提示：' + state.meta.hint : '目前沒有設定提示';
    openSheet('sheet-settings');
  }

  // ============================================================
  // 共用：按鈕忙碌狀態
  // ============================================================

  async function withBusy(btnId, text, fn) {
    if (state.busy) return;
    state.busy = true;
    const b = $(btnId);
    const orig = b.textContent;
    b.disabled = true;
    b.textContent = text;
    try {
      await fn();
    } catch (e) {
      if (!e.handled) toast(e.message || '發生錯誤');
    } finally {
      b.disabled = false;
      b.textContent = orig;
      state.busy = false;
    }
  }

  // ============================================================
  // 事件
  // ============================================================

  function bind() {
    $('setup-submit').addEventListener('click', onSetup);
    $('setup-pw').addEventListener('input', function () {
      const pw = $('setup-pw').value;
      renderStrength('setup-strength-bar', pw);
      $('setup-strength-text').textContent = pw ? ['太弱', '弱', '普通', '強', '很強'][VC.passwordStrength(pw)] : '';
    });
    $('rc-done').addEventListener('click', onRecoveryCodeDone);
    $('unlock-form').addEventListener('submit', onUnlock);
    $('unlock-hint-btn').addEventListener('click', function () { $('unlock-hint').hidden = !$('unlock-hint').hidden; });
    $('unlock-forgot').addEventListener('click', function () { setError('rec-error', ''); show('screen-recover'); $('rec-code').focus(); });
    $('rec-submit').addEventListener('click', onRecover);
    $('rec-back').addEventListener('click', function () { $('rec-code').value = ''; showUnlock(''); });
    $('nm-submit').addEventListener('click', onNewMaster);
    $('nm-pw').addEventListener('input', function () { renderStrength('nm-strength-bar', $('nm-pw').value); });
    $('message-retry').addEventListener('click', function () { location.reload(); });
    $('message-relogin').addEventListener('click', relogin);

    $('btn-lock').addEventListener('click', function () { lock('已鎖定'); });
    $('btn-settings').addEventListener('click', openSettings);
    $('btn-add').addEventListener('click', function () { openEdit(null, null); });
    $('search').addEventListener('input', renderList);

    $('d-reveal').addEventListener('click', toggleReveal);
    $('d-copy-user').addEventListener('click', function () { if (state.detail && state.detail.secret) copyText(state.detail.secret.username || ''); });
    $('d-copy-pass').addEventListener('click', function () { if (state.detail && state.detail.secret) copyText(state.detail.secret.password || ''); });
    $('d-edit').addEventListener('click', function () { const d = state.detail; if (d && d.secret) openEdit(d.item, d.secret); });
    $('d-delete').addEventListener('click', onDelete);
    $('d-url').addEventListener('click', function (ev) {
      ev.preventDefault();
      const url = $('d-url').href;
      if (!/^https?:\/\//i.test(url)) return;
      if (window.liff && liff.isInClient && liff.isInClient()) liff.openWindow({ url: url, external: true });
      else window.open(url, '_blank', 'noopener,noreferrer');
    });

    fillCategorySelect();
    $('e-cat').addEventListener('change', fillSubSuggestions);
    $('e-save').addEventListener('click', onSave);
    $('e-pass-toggle').addEventListener('click', function () { const p = $('e-pass'); p.type = p.type === 'password' ? 'text' : 'password'; });
    $('e-gen').addEventListener('click', function () {
      $('e-pass').value = VC.generatePassword(Number($('e-gen-len').value) || 16, { symbols: $('e-gen-sym').checked });
      $('e-pass').type = 'text';
    });

    $('s-new').addEventListener('input', function () { renderStrength('s-strength-bar', $('s-new').value); });
    $('s-rekey').addEventListener('click', onRekey);
    $('s-hint-save').addEventListener('click', onSaveHint);
    $('s-rc-new').addEventListener('click', onRegenRecovery);
    $('s-export').addEventListener('click', onExport);
    $('s-import').addEventListener('change', onImport);
    $('s-log-load').addEventListener('click', onLoadLog);
    $('s-lock').addEventListener('click', onEmergencyLock);

    document.querySelectorAll('[data-close]').forEach(function (b) {
      b.addEventListener('click', function () { closeSheet(b.closest('.sheet').id); });
    });
    document.querySelectorAll('.sheet').forEach(function (s) {
      s.addEventListener('click', function (ev) { if (ev.target === s) closeSheet(s.id); });
    });

    // 自動鎖定：有動作就重新計時；切到別的 App 或關掉畫面就立刻鎖定
    ['pointerdown', 'keydown', 'input', 'scroll'].forEach(function (evName) {
      document.addEventListener(evName, resetLockTimer, { passive: true, capture: true });
    });
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden' && (state.vk || state.recoverRaw || state.pending)) lock('切換到其他畫面，已自動鎖定');
    });
  }

  bind();
  boot();
})();
