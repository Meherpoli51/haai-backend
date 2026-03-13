require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// ════════════════════════════════════════════════════════════════════════════
// ── STARTUP VALIDATION — crash early if env is missing
// ════════════════════════════════════════════════════════════════════════════
const REQUIRED_ENV = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'ANTHROPIC_API_KEY',
  'GATE_HMAC_SECRET',   // NEW: used to sign gate tokens
  'ADMIN_SECRET',
  'ADMIN_EMAIL',        // MOVED: no longer hardcoded in source
];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error('[FATAL] Missing required environment variables:', missingEnv.join(', '));
  process.exit(1);
}

const app = express();

// ── Supabase admin client ─────────────────────────────────────────────────
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

app.use(express.json({ limit: '2mb' }));

// ── Credit costs per action ──────────────────────────────────────────────
const CREDIT_COSTS = {
  decode:      20,
  screen:       3,   // per CV
  boolean:      5,
  quick_score:  2,
  chat:         1,
};

const FREE_CREDITS_ON_SIGNUP = 100;

// ════════════════════════════════════════════════════════════════════════════
// ── GATE TOKEN — now HMAC-signed, not plain base64
// ════════════════════════════════════════════════════════════════════════════
const GATE_SECRET = process.env.GATE_HMAC_SECRET;
const GATE_TOKEN_TTL = 8 * 60 * 60 * 1000; // 8 hours

function signGateToken(payload) {
  const data = JSON.stringify({ ...payload, exp: Date.now() + GATE_TOKEN_TTL });
  const encoded = Buffer.from(data).toString('base64url');
  const sig = crypto
    .createHmac('sha256', GATE_SECRET)
    .update(encoded)
    .digest('hex');
  return `${encoded}.${sig}`;
}

function verifyGateToken(token) {
  if (!token || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  const expectedSig = crypto
    .createHmac('sha256', GATE_SECRET)
    .update(encoded)
    .digest('hex');
  // Constant-time comparison prevents timing attacks
  const sigBuf  = Buffer.from(sig, 'hex');
  const expBuf  = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    if (Date.now() > payload.exp) return null; // expired
    return payload;
  } catch { return null; }
}

// ════════════════════════════════════════════════════════════════════════════
// ── RATE LIMITING — Supabase-backed, survives restarts + multi-instance
// ════════════════════════════════════════════════════════════════════════════
// Uses the gate_attempts table in Supabase.
// SQL to create it (run once in Supabase SQL editor):
//
//   CREATE TABLE IF NOT EXISTS gate_attempts (
//     ip        TEXT NOT NULL,
//     attempted_at TIMESTAMPTZ DEFAULT NOW()
//   );
//   CREATE INDEX ON gate_attempts (ip, attempted_at);
//
async function checkRateLimit(ip) {
  const windowStart = new Date(Date.now() - 60_000).toISOString();
  const { count, error } = await supabase
    .from('gate_attempts')
    .select('*', { count: 'exact', head: true })
    .eq('ip', ip)
    .gte('attempted_at', windowStart);
  if (error) {
    // If table doesn't exist yet, fail open (don't block legitimate users)
    console.warn('[rate-limit] gate_attempts table missing — run the setup SQL:', error.message);
    return false;
  }
  return count >= 10;
}

async function recordAttempt(ip) {
  await supabase.from('gate_attempts').insert({ ip });
  // Clean up old entries (older than 2 minutes) — cheap housekeeping
  const cutoff = new Date(Date.now() - 120_000).toISOString();
  await supabase.from('gate_attempts').delete().lt('attempted_at', cutoff);
}

// ════════════════════════════════════════════════════════════════════════════
// ── JD DECODE CACHE — Supabase-backed, survives restarts
// ════════════════════════════════════════════════════════════════════════════
// SQL to create it (run once in Supabase SQL editor):
//
//   CREATE TABLE IF NOT EXISTS jd_decode_cache (
//     cache_key  TEXT PRIMARY KEY,
//     response   JSONB NOT NULL,
//     created_at TIMESTAMPTZ DEFAULT NOW()
//   );
//
const CACHE_TTL_HOURS = 24;

function getCacheKey(text) {
  return crypto.createHash('sha256').update(text.trim().toLowerCase()).digest('hex');
}

async function getCached(key) {
  const cutoff = new Date(Date.now() - CACHE_TTL_HOURS * 3600_000).toISOString();
  const { data, error } = await supabase
    .from('jd_decode_cache')
    .select('response')
    .eq('cache_key', key)
    .gte('created_at', cutoff)
    .single();
  if (error || !data) return null;
  return data.response;
}

async function setCache(key, response) {
  await supabase.from('jd_decode_cache').upsert({
    cache_key: key,
    response,
    created_at: new Date().toISOString()
  }, { onConflict: 'cache_key' });
}

// ════════════════════════════════════════════════════════════════════════════
// ── AUTH MIDDLEWARE
// ════════════════════════════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing auth token' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid or expired token' });

    req.user = user;

    let { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    if (profileError && profileError.code === 'PGRST116') {
      // First login — create profile. Admin email comes from env, never source code.
      const isAdmin = user.email === process.env.ADMIN_EMAIL;
      const startingCredits = isAdmin ? 1000 : FREE_CREDITS_ON_SIGNUP;
      const { data: newProfile, error: createError } = await supabase
        .from('profiles')
        .insert({
          id: user.id,
          email: user.email,
          name: user.user_metadata?.full_name || user.email.split('@')[0],
          avatar_url: user.user_metadata?.avatar_url || null,
          credits_remaining: startingCredits,
          credits_total_used: 0,
          plan: isAdmin ? 'admin' : 'free'
        })
        .select()
        .single();

      if (createError) return res.status(500).json({ error: 'Failed to create user profile' });
      profile = newProfile;
    } else if (profileError) {
      return res.status(500).json({ error: 'Failed to load user profile' });
    }

    req.profile = profile;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Auth failed: ' + e.message });
  }
}

// ════════════════════════════════════════════════════════════════════════════
// ── CREDITS — atomic deduct + refund on failure (fixes race condition)
// ════════════════════════════════════════════════════════════════════════════
// SECURITY FIX: credits are now deducted BEFORE the AI call.
// If the AI call fails, we refund. This prevents concurrent requests from
// all passing the credit check before any deduction lands.
//
// Your deduct_credits RPC must be atomic. Verify it uses:
//   UPDATE profiles SET
//     credits_remaining = credits_remaining - amount,
//     credits_total_used = credits_total_used + amount
//   WHERE id = user_id AND credits_remaining >= amount
// Add RETURNING credits_remaining to know the new balance.
//
async function deductCredits(userId, amount, action, metadata = {}) {
  const { error } = await supabase.rpc('deduct_credits', { user_id: userId, amount });
  if (error) throw new Error('Failed to deduct credits: ' + error.message);

  await supabase.from('usage_logs').insert({
    user_id: userId,
    action_type: action,
    credits_used: amount,
    metadata
  });
}

async function refundCredits(userId, amount, reason) {
  await supabase.rpc('refund_credits', { user_id: userId, amount });
  await supabase.from('usage_logs').insert({
    user_id: userId,
    action_type: 'refund',
    credits_used: -amount,
    metadata: { reason }
  });
  console.log(`[REFUND] ${userId} +${amount} credits — ${reason}`);
}

// ════════════════════════════════════════════════════════════════════════════
// ── ROUTES
// ════════════════════════════════════════════════════════════════════════════

// Health check
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now(), version: '3.0' }));

// ── POST /api/gate ────────────────────────────────────────────────────────
// Gate passwords: all values come from env vars. No defaults in source code.
// Add to Railway env: ADMIN_PASSWORD, RECRUIT1_PASSWORD … RECRUIT5_PASSWORD
app.post('/api/gate', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });

  const ip = req.ip || req.connection.remoteAddress;

  // Rate limit check (Supabase-backed, works across restarts)
  const limited = await checkRateLimit(ip);
  if (limited) {
    return res.status(429).json({ ok: false, error: 'Too many attempts. Wait 1 minute.' });
  }
  await recordAttempt(ip);

  // Gate user map — 100% from env vars, nothing hardcoded
  const GATE_USERS = {
    [process.env.ADMIN_PASSWORD]:    { name: 'Admin',       role: 'Administrator' },
    [process.env.RECRUIT1_PASSWORD]: { name: 'Recruiter 1', role: 'Recruiter' },
    [process.env.RECRUIT2_PASSWORD]: { name: 'Recruiter 2', role: 'Recruiter' },
    [process.env.RECRUIT3_PASSWORD]: { name: 'Recruiter 3', role: 'Recruiter' },
    [process.env.RECRUIT4_PASSWORD]: { name: 'Recruiter 4', role: 'Recruiter' },
    [process.env.RECRUIT5_PASSWORD]: { name: 'Recruiter 5', role: 'Recruiter' },
  };

  const user = GATE_USERS[password];
  if (user) {
    // SECURITY FIX: token is now HMAC-signed — cannot be forged or tampered
    const token = signGateToken({ name: user.name, role: user.role });
    return res.json({ ok: true, user, token });
  }
  return res.status(401).json({ ok: false, error: 'Invalid password' });
});

// ── GET /api/status ───────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
  const checks = { ok: true, ts: Date.now(), version: '3.0', services: {} };

  try {
    await supabase.from('profiles').select('id').limit(1);
    checks.services.database = 'ok';
  } catch(e) {
    checks.services.database = 'error: ' + e.message;
    checks.ok = false;
  }

  checks.services.ai = process.env.ANTHROPIC_API_KEY ? 'key loaded' : 'MISSING KEY';
  if (!process.env.ANTHROPIC_API_KEY) checks.ok = false;

  res.json(checks);
});

// ── GET /api/me ───────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const { id, email, name, avatar_url, credits_remaining, credits_total_used, plan } = req.profile;
  res.json({ id, email, name, avatar_url, credits_remaining, credits_total_used, plan });
});

// ── POST /api/chat — Anthropic proxy with pre-deduction ──────────────────
app.post('/api/chat', requireAuth, async (req, res) => {
  const { action = 'chat', model, max_tokens, system, messages, cv_count = 1 } = req.body;

  if (!CREDIT_COSTS[action]) {
    return res.status(400).json({ error: `Unknown action: ${action}` });
  }
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages array is required' });
  }

  const baseCost = CREDIT_COSTS[action];
  const multiplier = action === 'screen' ? (cv_count || 1) : 1;
  const totalCost = baseCost * multiplier;

  if (req.profile.credits_remaining < totalCost) {
    return res.status(402).json({
      error: 'insufficient_credits',
      message: `This action costs ${totalCost} credits. You have ${req.profile.credits_remaining} remaining.`,
      credits_remaining: req.profile.credits_remaining,
      credits_needed: totalCost
    });
  }

  try {
    // ── Cache check — free, no deduction ─────────────────────────────────
    let cacheKey = null;
    if (action === 'decode' && messages?.[0]?.content) {
      cacheKey = getCacheKey(typeof messages[0].content === 'string'
        ? messages[0].content
        : JSON.stringify(messages[0].content));
      const cached = await getCached(cacheKey);
      if (cached) {
        console.log(`[CACHE HIT] decode ${cacheKey.substring(0, 8)}… — saved ${totalCost} credits`);
        res.setHeader('X-Credits-Remaining', req.profile.credits_remaining);
        res.setHeader('X-Cache', 'HIT');
        return res.json(cached);
      }
    }

    // ── SECURITY FIX: Deduct BEFORE the AI call ───────────────────────────
    // If two requests arrive simultaneously, only one can deduct (RPC is atomic).
    // The second will fail the credit check at the RPC level.
    await deductCredits(req.user.id, totalCost, action, {
      model: model || 'claude-sonnet-4-6',
      cv_count: action === 'screen' ? cv_count : undefined
    });

    // ── Call Anthropic ────────────────────────────────────────────────────
    let anthropicRes;
    try {
      anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: model || 'claude-sonnet-4-6',
          max_tokens: max_tokens || 4000,
          system,
          messages
        })
      });
    } catch (networkErr) {
      // Network error — refund and return error
      await refundCredits(req.user.id, totalCost, 'network_error');
      return res.status(503).json({ error: 'Could not reach AI service. Your credits have been refunded.' });
    }

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.json().catch(() => ({}));
      const status = anthropicRes.status;

      // Refund on all non-success responses
      await refundCredits(req.user.id, totalCost, `anthropic_${status}`);

      if (status === 429) {
        const retryAfter = anthropicRes.headers.get('retry-after') || 30;
        return res.status(429).json({
          error: 'rate_limited',
          message: `AI is busy. Your credits have been refunded. Please wait ${retryAfter}s and try again.`,
          retry_after: retryAfter
        });
      }
      if (status === 529 || status === 503) {
        return res.status(503).json({
          error: 'ai_overloaded',
          message: 'AI service is overloaded. Your credits have been refunded. Try again in 30 seconds.'
        });
      }
      if (status === 401) {
        console.error('[CRITICAL] Anthropic API key invalid');
        return res.status(500).json({ error: 'AI configuration error. Credits refunded. Contact support.' });
      }

      return res.status(status).json({
        error: errBody.error?.message || `AI error ${status}. Credits refunded.`
      });
    }

    const data = await anthropicRes.json();

    // Cache successful decode responses
    if (action === 'decode' && cacheKey) {
      await setCache(cacheKey, data);
      console.log(`[CACHE SET] decode ${cacheKey.substring(0, 8)}…`);
    }

    const newBalance = req.profile.credits_remaining - totalCost;
    res.setHeader('X-Credits-Remaining', newBalance);
    res.setHeader('X-Credits-Used', totalCost);
    res.json(data);

  } catch (e) {
    console.error('[CHAT ERROR]', e.message);
    // Attempt refund on unexpected errors
    try { await refundCredits(req.user.id, totalCost, 'unexpected_error'); } catch {}
    res.status(500).json({ error: 'Unexpected error. Credits have been refunded.' });
  }
});

// ── GET /api/credits ──────────────────────────────────────────────────────
app.get('/api/credits', requireAuth, (req, res) => {
  res.json({
    credits_remaining: req.profile.credits_remaining,
    credits_total_used: req.profile.credits_total_used,
    plan: req.profile.plan,
    costs: CREDIT_COSTS
  });
});

// ── GET /api/usage ────────────────────────────────────────────────────────
app.get('/api/usage', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('usage_logs')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ usage: data });
});

// ── POST /api/admin/topup ─────────────────────────────────────────────────
app.post('/api/admin/topup', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { email, credits } = req.body;
  if (!email || !credits || typeof credits !== 'number' || credits <= 0) {
    return res.status(400).json({ error: 'email and positive credits required' });
  }

  const { data: profile, error } = await supabase
    .from('profiles')
    .select('id, credits_remaining')
    .eq('email', email)
    .single();

  if (error || !profile) return res.status(404).json({ error: 'User not found' });

  const { error: updateError } = await supabase
    .from('profiles')
    .update({ credits_remaining: profile.credits_remaining + credits })
    .eq('id', profile.id);

  if (updateError) return res.status(500).json({ error: updateError.message });

  await supabase.from('usage_logs').insert({
    user_id: profile.id,
    action_type: 'admin_topup',
    credits_used: -credits,
    metadata: { by: 'admin', email }
  });

  res.json({ ok: true, new_balance: profile.credits_remaining + credits });
});

// ── POST /api/candidates ──────────────────────────────────────────────────
app.post('/api/candidates', requireAuth, async (req, res) => {
  const { fingerprint, name, score, verdict, hire_decision, jd_snippet, metadata } = req.body;
  if (!fingerprint || !name) return res.status(400).json({ error: 'fingerprint and name required' });

  const { data, error } = await supabase
    .from('candidates')
    .upsert({
      user_id: req.user.id,
      fingerprint,
      name,
      score: score || 0,
      verdict: verdict || '',
      hire_decision: hire_decision || '',
      jd_snippet: jd_snippet || '',
      metadata: metadata || {},
      seen_at: new Date().toISOString()
    }, { onConflict: 'user_id,fingerprint' })
    .select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true, candidate: data });
});

// ── GET /api/candidates ───────────────────────────────────────────────────
app.get('/api/candidates', requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 200, 500);
  const { data, error } = await supabase
    .from('candidates')
    .select('*')
    .eq('user_id', req.user.id)
    .order('seen_at', { ascending: false })
    .limit(limit);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ candidates: data, count: data.length });
});

// ── DELETE /api/candidates ────────────────────────────────────────────────
app.delete('/api/candidates', requireAuth, async (req, res) => {
  const { error } = await supabase
    .from('candidates').delete().eq('user_id', req.user.id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── 404 + global error handler ────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route not found', path: req.path }));
app.use((err, req, res, next) => {
  console.error('[EXPRESS ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Crash-safe process handlers ───────────────────────────────────────────
process.on('uncaughtException',  (err)    => console.error('[UNCAUGHT]', err.message, err.stack));
process.on('unhandledRejection', (reason) => console.error('[UNHANDLED]', reason));

// ── Start server ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ HA.AI backend v3.0 on port ${PORT}`);
  console.log(`   Anthropic key  : ${process.env.ANTHROPIC_API_KEY ? '✓' : '✗ MISSING'}`);
  console.log(`   Supabase URL   : ${process.env.SUPABASE_URL ? '✓' : '✗ MISSING'}`);
  console.log(`   Gate secret    : ${process.env.GATE_HMAC_SECRET ? '✓' : '✗ MISSING — gate tokens insecure'}`);
  console.log(`   Allowed origins: ${process.env.ALLOWED_ORIGINS || 'not set'}`);
});

// ── Keep Railway free tier alive (remove once on paid plan) ───────────────
const SELF_URL = process.env.RAILWAY_STATIC_URL
  ? `https://${process.env.RAILWAY_STATIC_URL}`
  : `http://localhost:${PORT}`;

setInterval(async () => {
  try {
    const r = await fetch(`${SELF_URL}/health`);
    if (r.ok) console.log(`[keep-alive] ✓ ${new Date().toISOString()}`);
  } catch(e) { console.warn('[keep-alive] ping failed:', e.message); }
}, 10 * 60 * 1000);
