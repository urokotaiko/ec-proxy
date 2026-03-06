// =====================================================
// EC チェックツール用 プロキシサーバー
// セキュリティ対策済み（APIキー認証 + CORS + レートリミット）
// =====================================================

const express    = require('express');
const fetch      = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // Render環境でのプロキシ設定

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
      signal: AbortSignal.timeout(15000),
    });

    const contentType = response.headers.get('content-type') || 'text/html';
    const body = await response.text();

    res.status(response.status)
       .setHeader('Content-Type', contentType)
       .setHeader('X-Final-Url', response.url)
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
// OpenRouter API 中継エンドポイント
// ─────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));

app.post('/gemini', requireApiKey, async (req, res) => {
  try {
    const openrouterKey = process.env.OPENROUTER_API_KEY;
    if (!openrouterKey) {
      return res.status(500).json({ error: 'OPENROUTER_API_KEYが環境変数に設定されていません' });
    }

    const { prompt } = req.body;
    if (!prompt) {
      return res.status(400).json({ error: 'promptが必要です' });
    }

    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${openrouterKey}`,
        'HTTP-Referer': 'https://urokotaiko.github.io',
        'X-Title': 'EC Auto Checker',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.0-flash-exp:free',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens: 8192,
      }),
      signal: AbortSignal.timeout(120000),
    });

    const data = await response.json();

    if (data?.error) {
      console.error('OpenRouter APIエラー:', JSON.stringify(data.error));
      return res.status(500).json({ error: 'OpenRouter APIエラー: ' + (data.error.message || JSON.stringify(data.error)) });
    }

    const text = data?.choices?.[0]?.message?.content || '';
    if (!text) {
      console.error('OpenRouter 予期しないレスポンス:', JSON.stringify(data).slice(0, 500));
      return res.status(500).json({ error: '有効なレスポンスが得られませんでした' });
    }

    console.log('OpenRouter成功 テキスト長:', text.length);
    res.json({ text });

  } catch (err) {
    res.status(500).json({ error: 'OpenRouter API中継エラー：' + err.message });
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
  console.log(`   許可ドメイン : ${ALLOWED_ORIGINS ? ALLOWED_ORIGINS.join(', ') : '全て許可'}`);
  console.log(`   APIキー     : ${SECRET_KEY.slice(0, 4)}****（環境変数 PROXY_SECRET_KEY で変更可）`);
});
