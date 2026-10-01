// ============================================================
// White 密碼本：LIFF 網頁
// ------------------------------------------------------------
// 這個網頁只做：輸入主密碼打開、查詢、新增／修改／刪除帳密
//   主密碼的設定（建立、更換、救援碼）不在網頁上，是在電腦用主密碼工具產生後貼到 GAS 指令碼屬性
// 流程：LINE 身分（ID Token）→ 輸入主密碼 → 手機推導出「登入鑰」給後端驗證、「KEK」留在手機
//      → 後端驗證通過才給「包起來的密碼本金鑰」和清單 → 手機用 KEK 打開金鑰
// 安全原則：
//   ・帳號、密碼加密；名稱、分類、小分類、歸屬者、網址、備註不加密（直接存在試算表，方便在 Excel 查看）
//   ・主密碼、金鑰、帳號密碼明文只在這個網頁的記憶體裡，不存 localStorage、不寫 console
//   ・帳號密碼點開那一筆才下載、才解密，關掉就清掉
//   ・畫面一律用 textContent 放資料，不用 innerHTML，資料裡就算有 HTML 也不會被執行
//   ・5 分鐘沒動作、或切到別的 App 超過 2 分鐘，就清掉金鑰鎖定
// ============================================================
(function () {
  'use strict';

  const CFG = window.VAULT_CONFIG || {};
  const VC = window.VaultCrypto;
  // 本機預覽（localhost 或直接開檔案）才會用假的 LINE 身分；正式網址是 https，不會符合
  const IS_LOCAL = /^(localhost|127\.0\.0\.1)$/.test(location.hostname) || location.protocol === 'file:';
  // name：存在試算表裡的分類文字（試算表直接看得懂；在 Excel 改成這幾個字也認得）
  const CATEGORIES = [
    { key: 'home', label: '🏠 家庭', name: '家庭' },
    { key: 'school', label: '🏫 學校', name: '學校' },
    { key: 'finance', label: '💰 金融', name: '金融' },
    { key: 'shopping', label: '🛒 購物', name: '購物' },
    { key: 'work', label: '💼 工作', name: '工作' },
    { key: 'other', label: '📦 其他', name: '其他' }
  ];
  const state = {
    idToken: null,
    meta: null,        // { initialized, saltM, iterations, hint }
    session: null,     // 後端發的工作階段（15 分鐘）
    vk: null,          // 密碼本金鑰（CryptoKey，不可匯出）
    encrypted: null,   // 還沒解開的摘要
    items: [],         // [{ id, rev, updatedAt, updatedBy, s: 摘要明文 }]
    owners: [],        // 歸屬者下拉選項（GAS 的 VAULT_OWNERS，輸入主密碼後才拿得到）
    me: '',            // 自己對應的歸屬者（新增時預設選這個）
    favs: [],          // 常用項目 id 清單（從後端讀來，不存 localStorage）
    filterOwner: '',
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

  const SCREENS = ['screen-loading', 'screen-message', 'screen-unlock', 'screen-list'];
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
      '所有人都暫時打不開，資料不會刪除。\n確認安全後，到密碼本的 GAS 刪除指令碼屬性 VAULT_LOCKED 即可解除。', { retry: true });
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

  function showConfirm(msg, title) {
    return new Promise(function (resolve) {
      const ov = $('dlg-overlay');
      $('dlg-title').textContent = title || '確認';
      $('dlg-msg').textContent = msg;
      $('dlg-cancel').hidden = false;
      ov.hidden = false;

      function cleanup(res) {
        ov.hidden = true;
        $('dlg-ok').removeEventListener('click', onOk);
        $('dlg-cancel').removeEventListener('click', onCancel);
        resolve(res);
      }
      function onOk() { cleanup(true); }
      function onCancel() { cleanup(false); }

      $('dlg-ok').addEventListener('click', onOk);
      $('dlg-cancel').addEventListener('click', onCancel);
    });
  }

  function showAlert(msg, title) {
    return new Promise(function (resolve) {
      const ov = $('dlg-overlay');
      $('dlg-title').textContent = title || '提示';
      $('dlg-msg').textContent = msg;
      $('dlg-cancel').hidden = true;
      ov.hidden = false;

      function onOk() {
        ov.hidden = true;
        $('dlg-ok').removeEventListener('click', onOk);
        resolve();
      }
      $('dlg-ok').addEventListener('click', onOk);
    });
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
      else if (res.code === 'UNAUTHORIZED') {
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
      showMessage('🛠️', '密碼本還沒設定主密碼', '請管理者用電腦的「主密碼工具」產生設定，貼到密碼本 GAS 的指令碼屬性 VAULT_META。', { retry: true });
      return;
    }
    showUnlock(res.cooldown ? '錯太多次了，請 ' + Math.ceil(res.cooldown / 60) + ' 分鐘後再試' : '');
  }

  function showUnlock(errorText) {
    $('unlock-hint').hidden = !(state.meta && state.meta.hint);   // 有設定提示就直接顯示
    $('unlock-hint').textContent = state.meta && state.meta.hint ? '💡 主密碼提示：' + state.meta.hint : '';
    setError('unlock-error', errorText || '');
    show('screen-unlock');
    $('unlock-pw').focus();
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
      state.owners = res.owners || [];
      state.me = res.me || '';
      state.favs = res.favs || [];
      state.filterOwner = state.me;   // 打開時，歸屬者篩選預設選自己（按「👤 全部」看全部）
      $('unlock-pw').value = '';
      state.encrypted = res.entries;
      loadIndex();
      renderList();
      resetLockTimer();
    });
  }

  /** 清單（名稱、分類、小分類、歸屬者、網址、備註都是明文） */
  function loadIndex() {
    state.items = (state.encrypted || []).map(function (e) {
      return { id: e.id, rev: e.rev, updatedAt: e.updatedAt, updatedBy: e.updatedBy, s: fromServer(e.summary || {}) };
    });
    state.encrypted = null;
  }

  /** 試算表的明文摘要 → 網頁用的格式（分類文字 → key） */
  function fromServer(s) {
    const c = CATEGORIES.filter(function (x) { return x.name === s.category || x.key === s.category; })[0];
    return { name: s.name || '', category: c ? c.key : 'other', subcategory: s.subcategory || '', owner: s.owner || '', url: s.url || '', note: s.note || '' };
  }

  function toServer(s) {
    const c = CATEGORIES.filter(function (x) { return x.key === s.category; })[0];
    return { name: s.name, category: c ? c.name : '其他', subcategory: s.subcategory || '', owner: s.owner || '', url: s.url || '', note: s.note || '' };
  }

  async function reloadIndex() {
    const res = await api('getIndex');
    state.encrypted = res.entries;
    loadIndex();
    renderList();
  }

  /** 清掉所有機密（金鑰、工作階段、解開的資料、畫面上的欄位） */
  function clearSecrets() {
    if (state.session) api('logout').catch(function () {});
    state.vk = null;
    state.session = null;
    state.items = [];
    state.owners = [];
    state.me = '';
    state.favs = [];
    state.filterOwner = '';
    state.encrypted = null;
    ['sheet-detail', 'sheet-edit'].forEach(closeSheet);
    ['search', 'unlock-pw'].forEach(function (id) { $(id).value = ''; });
    if ($('search-clear')) $('search-clear').hidden = true;
    if ($('filter-owner')) $('filter-owner').value = '';
    if ($('owner-wrap')) $('owner-wrap').classList.remove('active');
    $('list').textContent = '';
    clearTimeout(state.lockTimer);
  }

  function lock(reason) {
    const wasOpen = !!state.vk;
    clearSecrets();
    if (!wasOpen && !reason) return;
    showUnlock(reason || '');
  }

  function resetLockTimer() {
    clearTimeout(state.lockTimer);
    if (state.vk) state.lockTimer = setTimeout(function () { lock('已經 5 分鐘沒有動作，自動鎖定了'); }, CFG.AUTO_LOCK_MS || 300000);
  }

  // ============================================================
  // 常用項目（存在後端 GAS，每個人各自一份）
  // ============================================================

  function isFavorite(id) {
    return state.favs.indexOf(id) >= 0;
  }

  function toggleFavorite(id) {
    const idx = state.favs.indexOf(id);
    if (idx >= 0) {
      state.favs.splice(idx, 1);
    } else {
      state.favs.unshift(id);
    }
    const added = idx < 0;
    // 非同步送後端，不擋畫面更新
    api('saveFavs', { favs: state.favs.slice() }).catch(function () {});
    return added;
  }

  function updateFavBtn() {
    if (!state.detail || !state.detail.item) return;
    const isFav = isFavorite(state.detail.item.id);
    const b = $('d-fav');
    if (!b) return;
    b.textContent = isFav ? '⭐' : '☆';
    b.classList.toggle('on', isFav);
    b.setAttribute('aria-label', isFav ? '取消常用' : '加入常用');
  }

  // ============================================================
  // 清單
  // ============================================================

  function renderChips() {
    const box = $('chips');
    box.textContent = '';
    const allChips = [{ key: '', label: '全部' }, { key: 'fav', label: '⭐ 常用' }].concat(CATEGORIES);
    allChips.forEach(function (c) {
      const b = el('button', 'chip' + (state.filterCat === c.key ? ' on' : ''), c.label);
      b.type = 'button';
      b.addEventListener('click', function () { state.filterCat = c.key; renderList(); });
      box.appendChild(b);
    });
    const ob = $('owner-chips');
    if (ob) ob.hidden = true;
  }

  function renderOwnerSelect() {
    const wrap = $('owner-wrap');
    if (!wrap) return;
    const names = state.owners.slice();
    state.items.forEach(function (it) { if (it.s.owner && names.indexOf(it.s.owner) < 0) names.push(it.s.owner); });
    if (!names.length) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    const sel = $('filter-owner');
    const currentVal = state.filterOwner;
    sel.textContent = '';
    const optAll = el('option', null, '👤 所有人');
    optAll.value = '';
    sel.appendChild(optAll);
    names.forEach(function (n) {
      const label = n === state.me ? '👤 ' + n + ' (我)' : '👤 ' + n;
      const o = el('option', null, label);
      o.value = n;
      sel.appendChild(o);
    });
    sel.value = currentVal;
    wrap.classList.toggle('active', !!currentVal);
  }

  function matches(item, q) {
    if (state.filterCat === 'fav') {
      if (!isFavorite(item.id)) return false;
    } else if (state.filterCat && item.s.category !== state.filterCat) {
      return false;
    }
    if (state.filterOwner && item.s.owner !== state.filterOwner) return false;
    if (!q) return true;
    const hay = [item.s.name, item.s.owner, item.s.subcategory, item.s.url, item.s.note, catLabel(item.s.category)].join(' ').toLowerCase();
    return q.toLowerCase().split(/\s+/).filter(Boolean).every(function (w) { return hay.indexOf(w) >= 0; });
  }

  function createItemButton(it) {
    const b = el('button', 'item');
    b.type = 'button';
    const left = el('div');
    left.className = 'item-main';
    const nameWrap = el('div', 'item-name');
    if (isFavorite(it.id)) {
      nameWrap.appendChild(el('span', 'item-star', '⭐ '));
    }
    nameWrap.appendChild(document.createTextNode(it.s.name));
    left.appendChild(nameWrap);
    const extra = [it.s.url ? it.s.url.replace(/^https?:\/\//, '') : '', it.s.note].filter(Boolean).join('・');
    if (extra) left.appendChild(el('div', 'item-sub', extra));
    b.appendChild(left);
    if (it.s.owner) b.appendChild(el('span', 'item-owner', '擁有人：' + it.s.owner));
    b.appendChild(el('span', 'item-arrow', '›'));
    b.addEventListener('click', function () { openDetail(it); });
    return b;
  }

  function renderList() {
    show('screen-list');
    renderChips();
    renderOwnerSelect();
    const q = $('search').value.trim();
    const list = $('list');
    list.textContent = '';
    const shown = state.items.filter(function (it) { return matches(it, q); });
    if (!shown.length) {
      if (state.filterCat === 'fav') {
        list.appendChild(el('div', 'empty', '目前還沒有加入常用項目\n點開任何項目按右上角「☆」即可加入'));
      } else {
        list.appendChild(el('div', 'empty', state.items.length ? '找不到符合的項目' : '還沒有任何資料，按右上角的「＋ 新增項目」開始'));
      }
      return;
    }
    // 常用分組：選了「⭐ 常用」或在「全部」且有常用項目時置頂顯示
    const favItems = shown.filter(function (it) { return isFavorite(it.id); });
    if (state.filterCat === 'fav') {
      const g = el('div', 'group group-fav');
      g.appendChild(el('div', 'group-title', '⭐ 常用項目（' + favItems.length + '）'));
      favItems.forEach(function (it) { g.appendChild(createItemButton(it)); });
      list.appendChild(g);
      return;
    }
    if (!state.filterCat && favItems.length) {
      const g = el('div', 'group group-fav');
      g.appendChild(el('div', 'group-title', '⭐ 常用項目（' + favItems.length + '）'));
      favItems.forEach(function (it) { g.appendChild(createItemButton(it)); });
      list.appendChild(g);
    }
    // 分類 → 標籤（小分類）區塊 → 名稱
    CATEGORIES.forEach(function (c) {
      const inCat = shown.filter(function (it) { return (it.s.category || 'other') === c.key; });
      if (!inCat.length) return;
      const g = el('div', 'group');
      g.appendChild(el('div', 'group-title', c.label + '（' + inCat.length + '）'));
      const subs = {};
      inCat.forEach(function (it) { const k = it.s.subcategory || ''; (subs[k] = subs[k] || []).push(it); });
      Object.keys(subs).sort(function (a, b) { return (a === '') - (b === '') || a.localeCompare(b, 'zh-Hant'); }).forEach(function (sub) {
        const items = subs[sub].sort(function (a, b) { return a.s.name.localeCompare(b.s.name, 'zh-Hant'); });
        if (sub) {
          // 有標籤：區塊容器，標籤置於左上角
          const block = el('div', 'sub-block');
          block.appendChild(el('div', 'sub-block-tag', '🏷️ ' + sub + '（' + items.length + '）'));
          items.forEach(function (it) {
            block.appendChild(createItemButton(it));
          });
          g.appendChild(block);
        } else {
          // 未分類標籤的項目
          items.forEach(function (it) {
            g.appendChild(createItemButton(it));
          });
        }
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
    $('d-owner-row').hidden = !item.s.owner;
    $('d-owner').textContent = item.s.owner || '';
    $('d-user').textContent = '解密中…';
    $('d-pass').textContent = '••••••••';
    $('d-url-row').hidden = !item.s.url;
    $('d-url').textContent = item.s.url || '';
    $('d-url').href = /^https?:\/\//i.test(item.s.url || '') ? item.s.url : '#';
    $('d-note-row').hidden = !item.s.note;
    $('d-note').textContent = item.s.note || '';
    $('d-meta').textContent = '最後修改：' + (item.updatedBy || '') + ' ' + fmtTime(item.updatedAt);
    updateFavBtn();
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
    const ok = await showConfirm('確定要刪除「' + d.item.s.name + '」嗎？\n刪除後無法復原。', '刪除項目');
    if (!ok) return;
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

  /** 歸屬者：GAS 設定的名單；舊資料的歸屬者如果已經不在名單裡，也保留成一個選項 */
  function fillOwnerSelect(current) {
    const sel = $('e-owner');
    sel.textContent = '';
    const names = state.owners.slice();
    if (current && names.indexOf(current) < 0) names.push(current);
    [''].concat(names).forEach(function (n) {
      const o = el('option', null, n || '（未指定）');
      o.value = n;
      sel.appendChild(o);
    });
    sel.value = current || '';
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
    $('e-title').textContent = item ? '✏️ 修改項目' : '＋ 新增項目';
    $('e-name-warn').hidden = true;
    $('e-name').value = item ? item.s.name : '';
    fillOwnerSelect(item ? item.s.owner : (state.filterOwner || state.me));
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
    $('e-name-warn').hidden = true;
    ['e-name', 'e-sub', 'e-url', 'e-note', 'e-user', 'e-pass'].forEach(function (id) { $(id).value = ''; });
  }

  async function onSave() {
    const summary = {
      name: $('e-name').value.trim(),
      owner: $('e-owner').value,
      category: $('e-cat').value,
      subcategory: $('e-sub').value.trim(),
      url: $('e-url').value.trim(),
      note: $('e-note').value.trim()
    };
    const secret = { username: $('e-user').value, password: $('e-pass').value };
    if (!summary.name) {
      $('e-name-warn').hidden = false;
      $('e-name').focus();
      return;
    }
    $('e-name-warn').hidden = true;
    if (summary.url && !/^https?:\/\//i.test(summary.url)) return setError('e-error', '網址要用 http:// 或 https:// 開頭');
    setError('e-error', '');
    const item = state.editing && state.editing.item;
    const id = item ? item.id : VC.newId();
    await withBusy('e-save', '儲存中…', async function () {
      try {
        const res = await api('saveEntry', {
          id: id,
          rev: item ? item.rev : 0,
          summary: toServer(summary),   // 名稱、分類…不加密，直接存在試算表
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

  async function handleSaveError(e) {
    if (e.handled) return;
    if (e.code === 'CONFLICT' || e.code === 'NOT_FOUND') {
      await showAlert(e.message + '\n\n會重新讀取最新的資料。', '資料已被變更');
      ['sheet-detail', 'sheet-edit'].forEach(closeSheet);
      reloadIndex().catch(function (err) { if (!err.handled) toast(err.message); });
    } else {
      toast(e.message || '儲存失敗');
    }
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
    $('unlock-form').addEventListener('submit', onUnlock);
    $('message-retry').addEventListener('click', function () { location.reload(); });
    $('message-relogin').addEventListener('click', relogin);

    $('btn-add').addEventListener('click', function () { openEdit(null, null); });
    $('search').addEventListener('input', function () {
      $('search-clear').hidden = !$('search').value;
      renderList();
    });
    $('search-clear').addEventListener('click', function () {
      $('search').value = '';
      $('search-clear').hidden = true;
      $('search').focus();
      renderList();
    });
    $('filter-owner').addEventListener('change', function () {
      state.filterOwner = this.value;
      renderList();
    });

    $('d-reveal').addEventListener('click', toggleReveal);
    $('d-fav').addEventListener('click', function () {
      if (!state.detail || !state.detail.item) return;
      const added = toggleFavorite(state.detail.item.id);
      updateFavBtn();
      renderList();
      toast(added ? '⭐ 已加入常用' : '已從常用移除');
    });
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
    $('e-name').addEventListener('input', function () { $('e-name-warn').hidden = true; });
    $('e-pass-toggle').addEventListener('click', function () { const p = $('e-pass'); p.type = p.type === 'password' ? 'text' : 'password'; });

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
    // 切到別的 App（例如去貼上剛複製的密碼）：2 分鐘內回來不用重新輸入主密碼，超過才鎖定
    let hiddenAt = 0;
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') { hiddenAt = Date.now(); return; }
      if (state.vk && hiddenAt && Date.now() - hiddenAt > (CFG.AWAY_LOCK_MS || 120000)) lock('離開超過 2 分鐘，已自動鎖定');
      hiddenAt = 0;
    });
  }

  bind();
  boot();
})();
