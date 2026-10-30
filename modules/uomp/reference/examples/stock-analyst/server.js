#!/usr/bin/env node
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { execSync } from 'child_process';
import { homedir } from 'os';
import { join } from 'path';
import { UompClient } from '@uomp/sdk';
import { mergeConfig, DEFAULT_CONFIG } from './lib/config.js';
import { fetchQuotes } from './lib/market.js';
import { analyze } from './lib/analysis.js';
import { generateJSON, generateMarkdown, generateHTML } from './lib/report.js';

const AGENT_ID = 'stock-analyst';
const AGENT_VERSION = '1.0.0';
const AGENT_NAME = 'UOMP Stock Analyst';

function getFingerprint() {
  const certPath = join(homedir(), '.uomp', '.gateway-certs', 'client.crt');
  if (!existsSync(certPath)) return null;
  try {
    const r = execSync(`openssl x509 -in "${certPath}" -noout -fingerprint -sha256`, { encoding: 'utf-8' });
    return r.trim().replace('sha256 Fingerprint=', '');
  } catch { return null; }
}

async function runAnalysis(token, gatewayUrl, sessionId, finnhubKey, userConfig) {
  const config = mergeConfig(userConfig);

  const uomp = new UompClient({ token, baseUrl: gatewayUrl, agentId: AGENT_ID, sessionId });

  const holdings = await uomp.memory.getByTag('portfolio:holdings');
  const riskItems = await uomp.memory.getByTag('profile:risk');
  const risk = riskItems[0]?.value ?? {};
  const symbols = [...new Set(holdings.map(h => h.value.symbol).filter(Boolean))];

  const quotes = await fetchQuotes(symbols, {
    finnhubKey,
    retries: config.rate_limit.retries,
    backoff_ms: config.rate_limit.backoff_ms,
    maxConcurrent: config.rate_limit.max_concurrent,
    benchmark: config.benchmark,
  });

  const analysis = analyze(holdings, risk, quotes, config);
  const results = {};

  if (config.report.include_json !== false) results.json = generateJSON(analysis);
  if (config.report.include_html !== false) results.html = generateHTML(analysis);
  if (config.report.include_markdown !== false) {
    for (const lang of config.languages) results[`markdown_${lang}`] = generateMarkdown(analysis, lang);
  }

  if (!existsSync('./output')) await mkdir('./output', { recursive: true });
  const ts = Date.now();
  if (results.html) await writeFile(`./output/stock-analysis-${ts}.html`, results.html, 'utf-8');
  if (results.json) await writeFile(`./output/stock-analysis-${ts}.json`, results.json, 'utf-8');
  await writeFile(`./output/stock-analysis-${ts}.md`, (results.markdown_zh || '') + '\n\n---\n\n' + (results.markdown_en || ''), 'utf-8');

  let payloadId = null;
  if (gatewayUrl.startsWith('https://') && sessionId) {
    try { payloadId = await uomp.payload.upload(results.json); } catch {}
    try { await uomp.session.submitDeletionProof(); } catch {}
  }

  return {
    summary: {
      holdings_count: holdings.length,
      total_pnl: analysis.totalPnl,
      total_pnl_pct: analysis.totalPnlPct,
      hhi: analysis.hhi,
      portfolio_volatility: analysis.portfolioVolatility,
      portfolio_sharpe: analysis.portfolioSharpe,
      signals_count: analysis.signals.length,
    },
    results,
    payload_id: payloadId,
    timestamp: analysis.timestamp,
  };
}

const app = new Hono();

// CORS for cross-origin dashboard
app.use('*', async (c, next) => {
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (c.req.method === 'OPTIONS') return new Response(null, { status: 204, headers: {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  }});
  await next();
});

app.get('/health', c => c.json({ status: 'ok', agent: AGENT_ID, version: AGENT_VERSION, name: AGENT_NAME }));

app.get('/fingerprint', c => {
  const fp = getFingerprint();
  if (!fp) return c.json({ error: 'No client certificate found' }, 404);
  c.header('Content-Type', 'text/plain');
  return c.body(`Add this fingerprint to your remote-profile.json agent_allowlist:\n\n${fp}\n`);
});

app.get('/', c => c.html(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${AGENT_NAME}</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#0A0A0A; color:#E5E7EB; display:flex; justify-content:center; align-items:center; min-height:100vh; padding:1rem; }
  .card { background:#111; border:1px solid #1F2937; border-radius:12px; padding:2rem; max-width:500px; width:100%; }
  h1 { font-size:1.5rem; color:#fff; margin-bottom:.5rem; }
  .subtitle { color:#9CA3AF; font-size:.9rem; margin-bottom:1.5rem; }
  label { display:block; font-size:.85rem; color:#D1D5DB; margin:.8rem 0 .3rem; }
  input, textarea { width:100%; padding:.6rem; background:#1A1A1A; border:1px solid #333; border-radius:6px; color:#E5E7EB; font-size:.85rem; }
  button { width:100%; padding:.7rem; margin-top:1rem; background:#3B82F6; border:none; border-radius:6px; color:#fff; font-size:.9rem; font-weight:600; cursor:pointer; }
  button:hover { background:#2563EB; }
  button:disabled { background:#374151; cursor:not-allowed; }
  #result { margin-top:1.5rem; padding:1rem; background:#1A1A1A; border-radius:6px; font-size:.85rem; white-space:pre-wrap; max-height:400px; overflow:auto; }
  .error { color:#F87171; } .success { color:#34D399; }
</style>
</head>
<body>
<div class="card">
  <h1>${AGENT_NAME}</h1>
  <p class="subtitle">v${AGENT_VERSION} · Analyze your portfolio via UOMP Gateway</p>
  <label for="token">Capability Token (UOM_TOKEN)</label>
  <input type="text" id="token" placeholder="eyJhbG...">
  <label for="gateway">Gateway URL (UOMP_BASE_URL)</label>
  <input type="text" id="gateway" placeholder="https://my-gateway.example.com" value="">
  <label for="session">Session ID (optional)</label>
  <input type="text" id="session" placeholder="sess_xxx">
  <label for="finnhub">Finnhub API Key (optional)</label>
  <input type="text" id="finnhub" placeholder="">
  <button id="analyzeBtn" onclick="run()">Analyze Portfolio</button>
  <div id="result"></div>
</div>
<script>
async function run() {
  const btn = document.getElementById('analyzeBtn'), res = document.getElementById('result');
  btn.disabled = true; res.textContent = 'Analyzing...';
  try {
    const r = await fetch('/analyze', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: document.getElementById('token').value,
        gateway_url: document.getElementById('gateway').value || 'http://127.0.0.1:9374',
        session_id: document.getElementById('session').value || undefined,
        finnhub_key: document.getElementById('finnhub').value || undefined,
      }),
    });
    const data = await r.json();
    if (!r.ok) { res.innerHTML = '<span class="error">Error: ' + JSON.stringify(data, null, 2) + '</span>'; }
    else {
      res.innerHTML = '<span class="success">Analysis complete</span>\n\n' +
        'Holdings: ' + data.summary.holdings_count + '\n' +
        'P&L: ' + data.summary.total_pnl + ' (' + data.summary.total_pnl_pct + '%)\n' +
        'HHI: ' + data.summary.hhi + ' | Vol: ' + (data.summary.portfolio_volatility ?? '-') + '% | Sharpe: ' + (data.summary.portfolio_sharpe ?? '-') + '\n' +
        'Signals: ' + data.summary.signals_count + (data.payload_id ? '\nPayload: ' + data.payload_id : '');
    }
  } catch(e) { res.innerHTML = '<span class="error">Connection error: ' + e.message + '</span>'; }
  finally { btn.disabled = false; }
}
</script>
</body>
</html>`));

app.post('/analyze', async c => {
  const body = await c.req.json();

  // Mode 1: Direct portfolio (browser dashboard — no Gateway needed)
  if (body.holdings && !body.token) {
    try {
      const holdings = body.holdings;
      const risk = body.risk || {};
      const symbols = [...new Set(holdings.map(h => h.value?.symbol).filter(Boolean))];
      const quotes = await fetchQuotes(symbols, { finnhubKey: body.finnhub_key || process.env.FINNHUB_KEY || '' });
      const config = mergeConfig(body.config || {});
      const analysis = analyze(holdings, risk, quotes.filter(q => q?.price != null), config);

      const results = {};
      if (config.report.include_json !== false) results.json = generateJSON(analysis);
      if (config.report.include_html !== false) results.html = generateHTML(analysis);
      if (config.report.include_markdown !== false) {
        for (const lang of config.languages) results[`markdown_${lang}`] = generateMarkdown(analysis, lang);
      }
      return c.json({
        summary: { holdings_count: holdings.length, total_pnl: analysis.totalPnl, total_pnl_pct: analysis.totalPnlPct,
          hhi: analysis.hhi, portfolio_volatility: analysis.portfolioVolatility, portfolio_sharpe: analysis.portfolioSharpe, signals_count: analysis.signals.length },
        results, timestamp: analysis.timestamp
      });
    } catch (err) { return c.json({ error: { code: 'ANALYSIS_FAILED', message: err.message } }, 500); }
  }

  // Mode 2: Gateway mode (existing — token + gateway_url)
  const token = body.token;
  if (!token) return c.json({ error: { code: 'INVALID_REQUEST', message: 'token is required' } }, 400);

  try {
    const result = await runAnalysis(
      token,
      body.gateway_url || 'http://127.0.0.1:9374',
      body.session_id || '',
      body.finnhub_key || process.env.FINNHUB_KEY || '',
      body.config || {}
    );
    return c.json(result);
  } catch (err) {
    return c.json({ error: { code: 'ANALYSIS_FAILED', message: err.message } }, 500);
  }
});

const port = parseInt(process.env.PORT || '3080', 10);
console.log(`UOMP Stock Analyst v${AGENT_VERSION}`);
console.log(`Server: http://0.0.0.0:${port}`);
const fp = getFingerprint();
if (fp) console.log(`Fingerprint: ${fp}`);

serve({ fetch: app.fetch, port, hostname: '0.0.0.0' });
