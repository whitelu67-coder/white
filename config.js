// 密碼本的設定（這些都不是秘密，放在公開的 GitHub 也沒關係）
window.VAULT_CONFIG = {
  // LINE Developers → LINE Login channel → LIFF 分頁的 LIFF ID，例如 '2001234567-AbCdEfGh'
  LIFF_ID: '2011821081-fqDntHsl',
  // 密碼本 GAS 部署後的網頁應用程式網址（…/exec）
  API_URL: 'https://script.google.com/macros/s/AKfycbyqfNGc8Y9pEqEnPc7XimXpeNaI3zSQYhrUS2GAOj2NBhXc-9a8qNuQr68D0jvC1lZ1gA/exec',
  // 5 分鐘沒動作自動鎖定
  AUTO_LOCK_MS: 5 * 60 * 1000,
  // 切到別的 App（例如去貼上密碼）超過 2 分鐘才鎖定；2 分鐘內回來不用重新輸入主密碼
  AWAY_LOCK_MS: 2 * 60 * 1000,
  // 顯示密碼 30 秒後自動遮住
  REVEAL_MS: 30 * 1000,
  // 只在 localhost 預覽時生效：用假的 LINE 身分和假的後端，方便在電腦上測畫面
  DEV_MOCK: true
};
