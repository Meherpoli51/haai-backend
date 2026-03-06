require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ── Supabase admin client (service role — never expose this to frontend) ──────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ── CORS — allow your Netlify domain + localhost for dev ──────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (mobile apps, Postman, extension)
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // Allow any localhost for dev
    if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

// ── Credit costs per action ───────────────────────────────────────────────────
const CREDIT_COSTS = {
  decode:       10,   // JD decode
  screen:        3,   // per CV screened
  boolean:       5,   // boolean string generation
  quick_score:   2,   // quick score a single card
  chat:          1,   // AI assistant message
};

const FREE_CREDITS_ON_SIGNUP = 100;

// ── Auth middleware — verifies Supabase JWT on every protected route ──────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing auth token' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    // Verify JWT with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Invalid or expired token' });

    req.user = user;

    // Fetch or create user profile with credits
    let { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    if (profileError && profileError.code === 'PGRST116') {
      // Profile doesn't exist yet — create it (first login)
      const { data: newProfile, error: createError } = await supabase
        .from('profiles')
        .insert({
          id: user.id,
          email: user.email,
          name: user.user_metadata?.full_name || user.email.split('@')[0],
          avatar_url: user.user_metadata?.avatar_url || null,
          credits_remaining: FREE_CREDITS_ON_SIGNUP,
          credits_total_used: 0,
          plan: 'free'
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

// ── Check + deduct credits middleware factory ─────────────────────────────────
function requireCredits(action, multiplierField = null) {
  return async (req, res, next) => {
    const baseCost = CREDIT_COSTS[action] || 1;
    // multiplierField: e.g. for 'screen', cost = 3 × number of CVs
    const multiplier = multiplierField ? (req.body[multiplierField] || 1) : 1;
    const totalCost = baseCost * multiplier;

    if (req.profile.credits_remaining < totalCost) {
      return res.status(402).json({
        error: 'insufficient_credits',
        message: `This action costs ${totalCost} credits. You have ${req.profile.credits_remaining} remaining.`,
        credits_remaining: req.profile.credits_remaining,
        credits_needed: totalCost
      });
    }

    req.creditCost = totalCost;
    req.creditAction = action;
    next();
  };
}

async function deductCredits(userId, amount, action, metadata = {}) {
  // Deduct from profile
  await supabase.rpc('deduct_credits', { user_id: userId, amount });

  // Log the usage
  await supabase.from('usage_logs').insert({
    user_id: userId,
    action_type: action,
    credits_used: amount,
    metadata
  });
}

// ════════════════════════════════════════════════════════════════════════════
// ── ROUTES
// ════════════════════════════════════════════════════════════════════════════

// Health check (no auth)
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ── GET /api/me — get current user profile + credits ─────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const { id, email, name, avatar_url, credits_remaining, credits_total_used, plan } = req.profile;
  res.json({ id, email, name, avatar_url, credits_remaining, credits_total_used, plan });
});

// ── POST /api/chat — main Anthropic proxy ─────────────────────────────────────
// Body: { action, model, max_tokens, system, messages, cv_count }
// action: 'decode' | 'screen' | 'boolean' | 'quick_score' | 'chat'
app.post('/api/chat', requireAuth, async (req, res) => {
  const { action = 'chat', model, max_tokens, system, messages, cv_count = 1 } = req.body;

  // Validate action
  if (!CREDIT_COSTS[action]) {
    return res.status(400).json({ error: `Unknown action: ${action}` });
  }

  // Calculate cost
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

  // Validate required fields
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'messages array is required' });
  }

  try {
    // Call Anthropic
    const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: model || 'claude-haiku-4-5-20251001',
        max_tokens: max_tokens || 2000,
        system,
        messages
      })
    });

    if (!anthropicRes.ok) {
      const errBody = await anthropicRes.json().catch(() => ({}));
      return res.status(anthropicRes.status).json({
        error: errBody.error?.message || `Anthropic API error ${anthropicRes.status}`
      });
    }

    const data = await anthropicRes.json();

    // ✅ Success — now deduct credits
    await deductCredits(req.user.id, totalCost, action, {
      model: model || 'claude-haiku-4-5-20251001',
      cv_count: action === 'screen' ? cv_count : undefined
    });

    // Return response + updated credit balance in headers
    res.setHeader('X-Credits-Remaining', req.profile.credits_remaining - totalCost);
    res.setHeader('X-Credits-Used', totalCost);
    res.json(data);

  } catch (e) {
    console.error('Anthropic proxy error:', e);
    res.status(500).json({ error: 'Proxy request failed: ' + e.message });
  }
});

// ── GET /api/credits — get credit balance ─────────────────────────────────────
app.get('/api/credits', requireAuth, (req, res) => {
  res.json({
    credits_remaining: req.profile.credits_remaining,
    credits_total_used: req.profile.credits_total_used,
    plan: req.profile.plan,
    costs: CREDIT_COSTS
  });
});

// ── GET /api/usage — usage history ────────────────────────────────────────────
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

// ── POST /api/admin/topup — add credits to a user (you use this manually) ─────
// Protected by admin secret header
app.post('/api/admin/topup', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { email, credits } = req.body;
  if (!email || !credits) return res.status(400).json({ error: 'email and credits required' });

  // Find user by email
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

  res.json({ ok: true, new_balance: profile.credits_remaining + credits });
});

// ── POST /api/candidates — store a scored candidate ──────────────────────────
app.post('/api/candidates', requireAuth, async (req, res) => {
  const { fingerprint, name, score, verdict, hire_decision, jd_snippet, metadata } = req.body;
  if (!fingerprint || !name) return res.status(400).json({ error: 'fingerprint and name required' });

  // Upsert — if same fingerprint exists, update score
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

// ── GET /api/candidates — get all seen candidates ─────────────────────────────
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

// ── DELETE /api/candidates — clear memory ─────────────────────────────────────
app.delete('/api/candidates', requireAuth, async (req, res) => {
  const { error } = await supabase
    .from('candidates')
    .delete()
    .eq('user_id', req.user.id);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`HA.AI backend running on port ${PORT}`);
  console.log(`Anthropic key: ${process.env.ANTHROPIC_API_KEY ? '✓ loaded' : '✗ MISSING'}`);
  console.log(`Supabase URL:  ${process.env.SUPABASE_URL ? '✓ loaded' : '✗ MISSING'}`);
});
