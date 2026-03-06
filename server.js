// =====================================================
// EC チェックツール用 プロキシサーバー
// セキュリティ対策済み（APIキー認証 + CORS + レートリミット）
// =====================================================

const express    = require('express');
const fetch      = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');

const app = express();

// ─────────────────────────────────────────────
// 設定（環境変数から読み込む）
// ─────────────────────────────────────────────
const PORT       = process.env.PORT       || 3001;
const SECRET_KEY = process.env.PROXY_SECRET_KEY || 'change-this-to-your-secret-key';

// ALLOWED_ORIGINSが環境変数に設定されていればそれを使う
// 設定がなければ GitHub Pages・localhost・file:// を全て許可
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : null; // nullの場合は全許可

// ─────────────────────────────────────────────
// ① CORS：許可するドメインを制限
// ─────────────────────────────────────────────
app.use(cors({
  origin: (origin, callback) => {
    // ALLOWED_ORIGINSが未設定の場合は全て許可（開発・GitHub Pages対応）
    if (!ALLOWED_ORIGINS) {
      return callback(null, true);
    }
    // originがない（curl・同一オリジン）またはnull（file://）は許可
    if (!origin || origin === 'null') {
      return callback(null, true);
    }
    // GitHub PagesのURLパターンを自動許可（*.github.io）
    if (/^https:\/\/[^.]+\.github\.io$/.test(origin)) {
      return callback(null, true);
    }
    // localhostは常に許可（開発用）
    if (/^https?:\/\/localhost(:\d+)?$/.test(origin) ||
        /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)) {
      return callback(null, true);
    }
    // 明示的に許可されたドメイン
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error('このドメインからのアクセスは許可されていません: ' + origin));
  }
}));

// ─────────────────────────────────────────────
// ② レートリミット：1分間に30回まで
// ─────────────────────────────────────────────
const limiter = rateLimit({
  windowMs : 60 * 1000,  // 1分
  max      : 30,
  message  : { error: 'アクセスが多すぎます。1分後に再試行してください。' }
});
app.use('/fetch', limiter);

// ─────────────────────────────────────────────
// ③ APIキー認証ミドルウェア
// ─────────────────────────────────────────────
function requireApiKey(req, res, next) {
  const key = req.headers['x-proxy-key'];
  if (!key || key !== SECRET_KEY) {
    return res.status(403).json({ error: '認証エラー：APIキーが正しくありません' });
  }
  next();
}

// ─────────────────────────────────────────────
// メインエンドポイント：URLのHTMLを取得する
// ─────────────────────────────────────────────
app.get('/fetch', requireApiKey, async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'urlパラメータが必要です' });
  }

  // httpまたはhttpsのみ許可（javascript:// などを弾く）
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ error: 'http または https のURLのみ対応しています' });
  }

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; ECChecker/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'ja,en;q=0.9',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(15000),  // 15秒タイムアウト
    });

    const contentType = response.headers.get('content-type') || 'text/html';
    const body = await response.text();

    res.status(response.status)
       .setHeader('Content-Type', contentType)
       .setHeader('X-Final-Url', response.url)           // リダイレクト後の最終URL
       .setHeader('X-Status-Code', response.status)
       .send(body);

  } catch (err) {
    if (err.name === 'TimeoutError') {
      return res.status(504).json({ error: 'タイムアウト：サイトの応答が遅すぎます（15秒超過）' });
    }
    res.status(500).json({ error: '取得失敗：' + err.message });
  }
});

// ─────────────────────────────────────────────
// ヘルスチェック（Renderが生存確認に使う）
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'ECプロキシサーバー 稼働中' });
});

// ─────────────────────────────────────────────
// 起動
// ─────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ ECプロキシサーバー起動中`);
  console.log(`   ポート      : ${PORT}`);
  console.log(`   許可ドメイン : ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`   APIキー     : ${SECRET_KEY.slice(0, 4)}****（環境変数 PROXY_SECRET_KEY で変更可）`);
});
