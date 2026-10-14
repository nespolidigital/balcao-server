/**
 * Servidor de validação de assinaturas do Balcão.
 *
 * O app nunca libera o Premium sozinho: depois de uma compra ou restauração,
 * o purchaseToken da Google Play é conferido aqui na Google Play Developer API.
 * O estado devolvido vai assinado (HMAC-SHA256) com PREMIUM_SIGNING_SECRET.
 *
 * Assinatura no Play Console: produto "balcao_premium" com os planos
 * básicos "monthly" e "yearly".
 *
 * Rotas:
 *   POST /api/premium/activate  { purchaseToken }   -> compra nova ou restauração
 *   POST /api/premium/verify    { premiumState }    -> revalida o estado salvo no app
 *   GET  /                                          -> saúde (Render)
 */

const express = require('express');
const crypto = require('crypto');
const { google } = require('googleapis');

const PORT = process.env.PORT || 3000;
const APP_SECRET = process.env.APP_SECRET;
const SIGNING_SECRET = process.env.PREMIUM_SIGNING_SECRET;
const PACKAGE_NAME = process.env.ANDROID_PACKAGE_NAME || 'com.balcao.app';
const PRODUCT_ID = 'balcao_premium';
const PLANOS = ['monthly', 'yearly'];

if (!APP_SECRET) console.warn('[balcao-server] APP_SECRET não configurado: todas as chamadas serão recusadas.');
if (!SIGNING_SECRET) console.warn('[balcao-server] PREMIUM_SIGNING_SECRET não configurado: nenhuma compra será liberada.');

const app = express();
app.set('trust proxy', 1); // Render fica atrás de proxy: req.ip vem do X-Forwarded-For
app.use(express.json({ limit: '20kb' }));

// CORS (o app chama a partir de https://localhost dentro do WebView)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-App-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- Limite por IP (as rotas consultam a API da Google). Só em memória. ---
const requestLog = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const recentes = (requestLog.get(ip) || []).filter((t) => now - t < 60000);
  if (recentes.length >= 20) {
    return res.status(429).json({ success: false, valid: false, error: 'Muitas tentativas. Aguarde um minuto.' });
  }
  recentes.push(now);
  requestLog.set(ip, recentes);
  next();
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, tempos] of requestLog) {
    const recentes = tempos.filter((t) => now - t < 60000);
    if (recentes.length) requestLog.set(ip, recentes);
    else requestLog.delete(ip);
  }
}, 5 * 60 * 1000).unref();

function requireAppToken(req, res, next) {
  const token = req.header('X-App-Token') || '';
  const a = Buffer.from(token);
  const b = Buffer.from(APP_SECRET || '');
  if (!APP_SECRET || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ success: false, valid: false, error: 'Token inválido.' });
  }
  next();
}

// --- Assinatura HMAC do estado Premium ---
function assinar(plan, expiresAt, purchaseToken) {
  if (!SIGNING_SECRET) return null;
  return crypto
    .createHmac('sha256', SIGNING_SECRET)
    .update(`${plan}|true|${expiresAt}|${purchaseToken}`)
    .digest('hex');
}

function assinaturaConfere(s) {
  const esperada = assinar(s.plan, s.expiresAt, s.purchaseToken);
  if (!esperada || typeof s.signature !== 'string') return false;
  const a = Buffer.from(s.signature);
  const b = Buffer.from(esperada);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function vencido(expiresAt) {
  const t = new Date(expiresAt).getTime();
  return !expiresAt || isNaN(t) || t < Date.now();
}

function estadoAssinado(plan, expiresAt, purchaseToken) {
  const signature = assinar(plan, expiresAt, purchaseToken);
  if (!signature) throw new Error('PREMIUM_SIGNING_SECRET não configurado.');
  return { isActive: true, plan, expiresAt, purchaseToken, signature };
}

// --- Google Play Developer API (conta de serviço) ---
let publisher = null;
function getPublisher() {
  if (!publisher) {
    const json = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    if (!json) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON não configurado.');
    const auth = new google.auth.GoogleAuth({
      credentials: JSON.parse(json),
      scopes: ['https://www.googleapis.com/auth/androidpublisher'],
    });
    publisher = google.androidpublisher({ version: 'v3', auth });
  }
  return publisher;
}

// Token que a Google não reconhece: compra inválida, não falha do servidor.
class TokenInvalido extends Error {}

/** Estado real da assinatura, vindo só da Google (nada do que o app afirma). */
async function consultarGoogle(purchaseToken) {
  if (typeof purchaseToken !== 'string' || purchaseToken.length < 10 || purchaseToken.length > 4096) {
    throw new TokenInvalido('purchaseToken inválido.');
  }
  const api = getPublisher();
  let data;
  try {
    ({ data } = await api.purchases.subscriptionsv2.get({ packageName: PACKAGE_NAME, token: purchaseToken }));
  } catch (err) {
    const status = Number(err?.code || err?.response?.status);
    if (status === 400 || status === 404 || status === 410) {
      throw new TokenInvalido('purchaseToken não reconhecido pela Google Play.');
    }
    throw err;
  }

  const item = (data.lineItems || []).find((li) => li.productId === PRODUCT_ID);
  if (!item) throw new TokenInvalido('A compra não é uma assinatura do Balcão.');

  const basePlan = item.offerDetails?.basePlanId;
  const plan = PLANOS.includes(basePlan) ? basePlan : 'monthly';
  const expiresAt = item.expiryTime || null;
  const ativa =
    ['SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD'].includes(data.subscriptionState) &&
    !vencido(expiresAt);

  // A Google estorna em 3 dias compras não reconhecidas. O plugin do app já
  // reconhece; confirmamos aqui também.
  if (ativa && data.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_PENDING') {
    try {
      await api.purchases.subscriptions.acknowledge({
        packageName: PACKAGE_NAME,
        subscriptionId: PRODUCT_ID,
        token: purchaseToken,
        requestBody: {},
      });
    } catch (err) {
      console.warn('[balcao-server] Falha ao reconhecer assinatura:', err?.message);
    }
  }

  return { ativa, plan, expiresAt, estado: data.subscriptionState };
}

app.post('/api/premium/activate', rateLimit, requireAppToken, async (req, res) => {
  const purchaseToken = req.body?.purchaseToken;
  if (!purchaseToken) return res.status(400).json({ success: false, error: 'purchaseToken é obrigatório.' });
  try {
    const r = await consultarGoogle(purchaseToken);
    if (!r.ativa) {
      return res.status(402).json({ success: false, error: `Assinatura não está ativa (${r.estado}).` });
    }
    return res.json({ success: true, premiumState: estadoAssinado(r.plan, r.expiresAt, purchaseToken) });
  } catch (err) {
    if (err instanceof TokenInvalido) return res.status(403).json({ success: false, error: err.message });
    console.error('[balcao-server] Erro ao validar compra:', err?.response?.data || err.message);
    return res.status(503).json({ success: false, error: 'Não foi possível validar a compra agora.' });
  }
});

// Estado assinado e dentro da validade: confirma sem consultar a Google.
// Vencido (renovação) ou sem assinatura válida: reconsulta a Google.
app.post('/api/premium/verify', rateLimit, requireAppToken, async (req, res) => {
  const s = req.body?.premiumState;
  if (!s || typeof s !== 'object' || !s.purchaseToken) return res.json({ valid: false });
  try {
    if (s.isActive === true && PLANOS.includes(s.plan) && assinaturaConfere(s) && !vencido(s.expiresAt)) {
      return res.json({ valid: true, premiumState: estadoAssinado(s.plan, s.expiresAt, s.purchaseToken) });
    }
    const r = await consultarGoogle(s.purchaseToken);
    if (!r.ativa) return res.json({ valid: false });
    return res.json({ valid: true, premiumState: estadoAssinado(r.plan, r.expiresAt, s.purchaseToken) });
  } catch (err) {
    if (err instanceof TokenInvalido) return res.json({ valid: false });
    console.error('[balcao-server] Erro ao verificar assinatura:', err?.response?.data || err.message);
    // 503 = não deu para confirmar agora (o app usa a tolerância de 7 dias)
    return res.status(503).json({ valid: false, error: 'Não foi possível verificar agora.' });
  }
});

app.get('/', (_req, res) => res.send('balcao-server: ok'));

app.listen(PORT, () => console.log(`[balcao-server] rodando na porta ${PORT}`));
