require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const Stripe  = require('stripe');
const { createClient } = require('@supabase/supabase-js');

// ════════════════════════════════════════════════════════════════════════════
// ── STARTUP VALIDATION
// ════════════════════════════════════════════════════════════════════════════
const REQUIRED_ENV = [
  'SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY',
  'ANTHROPIC_API_KEY', 'GATE_HMAC_SECRET',
  'ADMIN_SECRET', 'ADMIN_EMAIL',
  'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'FRONTEND_URL',
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error('[FATAL] Missing required env vars:', missingEnv.join(', '));
  process.exit(1);
}

const app    = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ── CORS ──────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true
}));

// ── CRITICAL: Stripe webhook must use raw body — register BEFORE express.json
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json({ limit: '2mb' }));

// ════════════════════════════════════════════════════════════════════════════
// ── CREDIT PACKS
// ════════════════════════════════════════════════════════════════════════════
const CREDIT_PACKS = {
  starter: {
    id:          'starter',
    name:        'Starter Pack',
    credits:     500,
    price_paise: 24900,    // ₹249 in paise
    price_inr:   249,
    description: '500 credits · ~25 JD decodes · ~166 CV screens',
    popular:     true,
  },
};

const CREDIT_COSTS = {
  decode: 20, screen: 3, boolean: 5, quick_score: 2, chat: 1,
};

const FREE_CREDITS_ON_SIGNUP = 100;

// ════════════════════════════════════════════════════════════════════════════
// ── GATE TOKEN (HMAC-signed)
// ════════════════════════════════════════════════════════════════════════════
const GATE_SECRET    = process.env.GATE_HMAC_SECRET;
const GATE_TOKEN_TTL = 8 * 60 * 60 * 1000;

function signGateToken(payload) {
  const data    = JSON.stringify({ ...payload, exp: Date.now() + GATE_TOKEN_TTL });
  const encoded = Buffer.from(data).toString('base64url');
  const sig     = crypto.createHmac('sha256', GATE_SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}

// ════════════════════════════════════════════════════════════════════════════
// ── RATE LIMITING (Supabase-backed)
// ════════════════════════════════════════════════════════════════════════════
async function checkRateLimit(ip) {
  const windowStart = new Date(Date.now() - 60_000).toISOString();
  const { count, error } = await supabase
    .from('gate_attempts').select('*', { count: 'exact', head: true })
    .eq('ip', ip).gte('attempted_at', windowStart);
  if (error) { console.warn('[rate-limit]', error.message); return false; }
  return count >= 10;
}

async function recordAttempt(ip) {
  await supabase.from('gate_attempts').insert({ ip });
  const cutoff = new Date(Date.now() - 120_000).toISOString();
  await supabase.from('gate_attempts').delete().lt('attempted_at', cutoff);
}

// ════════════════════════════════════════════════════════════════════════════
// ── JD DECODE CACHE (Supabase-backed)
// ════════════════════════════════════════════════════════════════════════════
function getCacheKey(text) {
  return crypto.createHash('sha256').update(text.trim().toLowerCase()).digest('hex');
}

async function getCached(key) {
  const cutoff = new Date(Date.now() - 24 * 3600_000).toISOString();
  const { data, error } = await supabase
    .from('jd_decode_cache').select('response')
    .eq('cache_key', key).gte('created_at', cutoff).single();
  if (error || !data) return null;
  return data.response;
}

async function setCache(key, response) {
  await supabase.from('jd_decode_cache').upsert(
    { cache_key: key, response, created_at: new Date().toISOString() },
    { onConflict: 'cache_key' }
  );
}

// ════════════════════════════════════════════════════════════════════════════
// ── AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing auth token' });

  const token = authHeader.replace('Bearer ', '');
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;

    let { data: profile, error: pe } = await supabase
      .from('profiles').select('*').eq('id', user.id).single();

    if (pe?.code === 'PGRST116') {
      const isAdmin = user.email === process.env.ADMIN_EMAIL;
      const { data: np, error: ce } = await supabase.from('profiles').insert({
        id: user.id, email: user.email,
        name: user.user_metadata?.full_name || user.email.split('@')[0],
        avatar_url: user.user_metadata?.avatar_url || null,
        credits_remaining: isAdmin ? 1000 : FREE_CREDITS_ON_SIGNUP,
        credits_total_used: 0, plan: isAdmin ? 'admin' : 'free'
      }).select().single();
      if (ce) return res.status(500).json({ error: 'Failed to create profile' });
      profile = np;
    } else if (pe) {
      return res.status(500).json({ error: 'Failed to load profile' });
    }

    req.profile = profile;
    next();
  } catch (e) { return res.status(401).json({ error: 'Auth failed: ' + e.message }); }
}

// ════════════════════════════════════════════════════════════════════════════
// ── CREDITS
// ════════════════════════════════════════════════════════════════════════════
async function deductCredits(userId, amount, action, metadata = {}) {
  const { error } = await supabase.rpc('deduct_credits', { user_id: userId, amount });
  if (error) throw new Error('Failed to deduct credits: ' + error.message);
  await supabase.from('usage_logs').insert({
    user_id: userId, action_type: action, credits_used: amount, metadata
  });
}

async function refundCredits(userId, amount, reason) {
  await supabase.rpc('refund_credits', { user_id: userId, amount });
  await supabase.from('usage_logs').insert({
    user_id: userId, action_type: 'refund', credits_used: -amount, metadata: { reason }
  });
}

// ════════════════════════════════════════════════════════════════════════════
// ── ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.get('/health', (req, res) =>
  res.json({ ok: true, ts: Date.now(), version: '4.0' }));

// ── POST /api/gate ────────────────────────────────────────────────────────
app.post('/api/gate', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });

  const ip = req.ip || req.connection.remoteAddress;
  if (await checkRateLimit(ip))
    return res.status(429).json({ ok: false, error: 'Too many attempts. Wait 1 minute.' });
  await recordAttempt(ip);

  const GATE_USERS = {
    [process.env.ADMIN_PASSWORD]:    { name: 'Admin',       role: 'Administrator' },
    [process.env.RECRUIT1_PASSWORD]: { name: 'Recruiter 1', role: 'Recruiter' },
    [process.env.RECRUIT2_PASSWORD]: { name: 'Recruiter 2', role: 'Recruiter' },
    [process.env.RECRUIT3_PASSWORD]: { name: 'Recruiter 3', role: 'Recruiter' },
    [process.env.RECRUIT4_PASSWORD]: { name: 'Recruiter 4', role: 'Recruiter' },
    [process.env.RECRUIT5_PASSWORD]: { name: 'Recruiter 5', role: 'Recruiter' },
  };

  const user = GATE_USERS[password];
  if (user) return res.json({ ok: true, user, token: signGateToken({ name: user.name, role: user.role }) });
  return res.status(401).json({ ok: false, error: 'Invalid password' });
});

// ── GET /api/me ───────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const { id, email, name, avatar_url, credits_remaining, credits_total_used, plan } = req.profile;
  res.json({ id, email, name, avatar_url, credits_remaining, credits_total_used, plan });
});

// ── GET /api/credits ──────────────────────────────────────────────────────
app.get('/api/credits', requireAuth, (req, res) => {
  res.json({
    credits_remaining:  req.profile.credits_remaining,
    credits_total_used: req.profile.credits_total_used,
    plan:  req.profile.plan,
    costs: CREDIT_COSTS,
    packs: CREDIT_PACKS,
  });
});

// ── GET /api/stripe/packs ─────────────────────────────────────────────────
app.get('/api/stripe/packs', (req, res) => {
  res.json({ packs: Object.values(CREDIT_PACKS) });
});

// ── POST /api/stripe/checkout ─────────────────────────────────────────────
app.post('/api/stripe/checkout', requireAuth, async (req, res) => {
  const { pack_id = 'starter' } = req.body;
  const pack = CREDIT_PACKS[pack_id];
  if (!pack) return res.status(400).json({ error: 'Invalid pack' });

  const FRONTEND = process.env.FRONTEND_URL.replace(/\/$/, '');

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode:     'payment',
      currency: 'inr',
      line_items: [{
        price_data: {
          currency:     'inr',
          unit_amount:  pack.price_paise,
          product_data: {
            name:        `HA.AI ${pack.name}`,
            description: pack.description,
          },
        },
        quantity: 1,
      }],
      metadata: {
        user_id:    req.user.id,
        user_email: req.user.email,
        pack_id,
        credits:    String(pack.credits),
      },
      customer_email: req.user.email,
      success_url: `${FRONTEND}/?payment=success&pack=${pack_id}&credits=${pack.credits}`,
      cancel_url:  `${FRONTEND}/?payment=cancelled`,
    });

    console.log(`[STRIPE] Checkout → ${req.user.email} | ${pack.name} | ₹${pack.price_inr}`);
    res.json({ url: session.url, session_id: session.id });

  } catch (e) {
    console.error('[STRIPE] Checkout error:', e.message);
    res.status(500).json({ error: 'Could not create checkout. Please try again.' });
  }
});

// ── POST /api/stripe/webhook ──────────────────────────────────────────────
// Handler declared here, registered at top of file with raw body parser
async function handleStripeWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('[WEBHOOK] Sig invalid:', e.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    if (session.payment_status !== 'paid')
      return res.json({ received: true, action: 'skipped_unpaid' });

    const { user_id, pack_id, credits, user_email } = session.metadata;
    if (!user_id || !credits) {
      console.error('[WEBHOOK] Missing metadata in session:', session.id);
      return res.status(400).json({ error: 'Missing metadata' });
    }

    const creditAmount = parseInt(credits, 10);

    try {
      // Add credits (reuse refund_credits RPC — it adds credits to balance)
      await supabase.rpc('refund_credits', { user_id, amount: creditAmount });

      // Log usage
      await supabase.from('usage_logs').insert({
        user_id,
        action_type: 'purchase',
        credits_used: -creditAmount,
        metadata: {
          pack_id,
          amount_paid_inr: session.amount_total / 100,
          stripe_session_id: session.id,
          email: user_email,
        }
      });

      // Log purchase record (for your revenue dashboard later)
      await supabase.from('purchases').insert({
        user_id,
        pack_id,
        credits_added:          creditAmount,
        amount_paise:           session.amount_total,
        stripe_session_id:      session.id,
        stripe_payment_intent:  session.payment_intent,
        status: 'completed',
      });

      console.log(`[WEBHOOK] ✅ ${user_email} paid ₹${session.amount_total / 100} → +${creditAmount} credits`);
      res.json({ received: true, credits_added: creditAmount });

    } catch (e) {
      console.error('[WEBHOOK] DB error:', e.message);
      return res.status(500).json({ error: 'DB error — Stripe will retry' });
    }
  } else {
    res.json({ received: true, action: 'ignored', type: event.type });
  }
}

// ── POST /api/chat ────────────────────────────────────────────────────────
app.post('/api/chat', requireAuth, async (req, res) => {
  const { action = 'chat', model, max_tokens, system, messages, cv_count = 1 } = req.body;

  if (!CREDIT_COSTS[action]) return res.status(400).json({ error: `Unknown action: ${action}` });
  if (!messages || !Array.isArray(messages)) return res.status(400).json({ error: 'messages array required' });

  const totalCost = CREDIT_COSTS[action] * (action === 'screen' ? (cv_count || 1) : 1);

  if (req.profile.credits_remaining < totalCost) {
    return res.status(402).json({
      error: 'insufficient_credits',
      message: `Costs ${totalCost} credits. You have ${req.profile.credits_remaining}.`,
      credits_remaining: req.profile.credits_remaining,
      credits_needed: totalCost,
      show_upgrade: true,   // frontend shows Buy Credits modal on this flag
    });
  }

  try {
    // Cache check
    let cacheKey = null;
    if (action === 'decode' && messages?.[0]?.content) {
      cacheKey = getCacheKey(
        typeof messages[0].content === 'string' ? messages[0].content : JSON.stringify(messages[0].content)
      );
      const cached = await getCached(cacheKey);
      if (cached) {
        res.setHeader('X-Credits-Remaining', req.profile.credits_remaining);
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }
    }

    // Deduct BEFORE AI call
    await deductCredits(req.user.id, totalCost, action, { model: model || 'claude-sonnet-4-6' });

    // Call Anthropic
    let anthropicRes;
    try {
      anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({ model: model || 'claude-sonnet-4-6', max_tokens: max_tokens || 4000, system, messages })
      });
    } catch (networkErr) {
      await refundCredits(req.user.id, totalCost, 'network_error');
      return res.status(503).json({ error: 'Could not reach AI. Credits refunded.' });
    }

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.json().catch(() => ({}));
      const status  = anthropicRes.status;
      await refundCredits(req.user.id, totalCost, `anthropic_${status}`);

      if (status === 429) {
        return res.status(429).json({ error: 'rate_limited', message: `AI busy. Credits refunded. Wait ${anthropicRes.headers.get('retry-after') || 30}s.` });
      }
      if (status === 529 || status === 503)
        return res.status(503).json({ error: 'ai_overloaded', message: 'AI overloaded. Credits refunded.' });
      return res.status(status).json({ error: errBody.error?.message || `AI error ${status}. Credits refunded.` });
    }

    const data = await anthropicRes.json();
    if (action === 'decode' && cacheKey) await setCache(cacheKey, data);

    res.setHeader('X-Credits-Remaining', req.profile.credits_remaining - totalCost);
    res.setHeader('X-Credits-Used', totalCost);
    res.json(data);

  } catch (e) {
    console.error('[CHAT ERROR]', e.message);
    try { await refundCredits(req.user.id, totalCost, 'unexpected_error'); } catch {}
    res.status(500).json({ error: 'Unexpected error. Credits refunded.' });
  }
});

// ── GET /api/usage ────────────────────────────────────────────────────────
app.get('/api/usage', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('usage_logs').select('*')
    .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ usage: data });
});

// ── POST /api/admin/topup ─────────────────────────────────────────────────
app.post('/api/admin/topup', async (req, res) => {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_SECRET)
    return res.status(403).json({ error: 'Forbidden' });
  const { email, credits } = req.body;
  if (!email || !credits || typeof credits !== 'number' || credits <= 0)
    return res.status(400).json({ error: 'email and positive credits required' });
  const { data: profile, error } = await supabase.from('profiles')
    .select('id, credits_remaining').eq('email', email).single();
  if (error || !profile) return res.status(404).json({ error: 'User not found' });
  await supabase.from('profiles')
    .update({ credits_remaining: profile.credits_remaining + credits }).eq('id', profile.id);
  res.json({ ok: true, new_balance: profile.credits_remaining + credits });
});

// ── /api/candidates CRUD ──────────────────────────────────────────────────
app.post('/api/candidates', requireAuth, async (req, res) => {
  const { fingerprint, name, score, verdict, hire_decision, jd_snippet, metadata } = req.body;
  if (!fingerprint || !name) return res.status(400).json({ error: 'fingerprint and name required' });
  const { data, error } = await supabase.from('candidates').upsert({
    user_id: req.user.id, fingerprint, name,
    score: score || 0, verdict: verdict || '',
    hire_decision: hire_decision || '', jd_snippet: jd_snippet || '',
    metadata: metadata || {}, seen_at: new Date().toISOString()
  }, { onConflict: 'user_id,fingerprint' }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, candidate: data });
});

app.get('/api/candidates', requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 500);
  const { data, error } = await supabase.from('candidates').select('*')
    .eq('user_id', req.user.id).order('seen_at', { ascending: false }).limit(limit);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ candidates: data, count: data.length });
});

app.delete('/api/candidates', requireAuth, async (req, res) => {
  const { error } = await supabase.from('candidates').delete().eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── GET /api/status ───────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
  const checks = { ok: true, ts: Date.now(), version: '4.0', services: {} };
  try { await supabase.from('profiles').select('id').limit(1); checks.services.database = 'ok'; }
  catch(e) { checks.services.database = 'error'; checks.ok = false; }
  checks.services.ai     = process.env.ANTHROPIC_API_KEY ? 'ok' : 'MISSING';
  checks.services.stripe = process.env.STRIPE_SECRET_KEY  ? 'ok' : 'MISSING';
  if (!process.env.ANTHROPIC_API_KEY) checks.ok = false;
  res.json(checks);
});

app.use((req, res) => res.status(404).json({ error: 'Route not found', path: req.path }));
app.use((err, req, res, next) => res.status(500).json({ error: 'Internal server error.' }));

process.on('uncaughtException',  err    => console.error('[UNCAUGHT]',  err.message, err.stack));
process.on('unhandledRejection', reason => console.error('[UNHANDLED]', reason));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ HA.AI v4.0 on port ${PORT}`);
  console.log(`   Stripe  : ${process.env.STRIPE_SECRET_KEY  ? '✓' : '✗ MISSING'}`);
  console.log(`   Frontend: ${process.env.FRONTEND_URL        || 'NOT SET'}`);
});

// Keep-alive ping (remove after upgrading Railway plan)
const SELF_URL = process.env.RAILWAY_STATIC_URL
  ? `https://${process.env.RAILWAY_STATIC_URL}` : `http://localhost:${PORT}`;
setInterval(async () => {
  try { await fetch(`${SELF_URL}/health`); }
  catch(e) { console.warn('[keep-alive] failed:', e.message); }
}, 10 * 60 * 1000);
