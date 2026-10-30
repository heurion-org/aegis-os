import { DEFAULT_CONFIG } from './config.js';

const YAHOO_CHART = 'https://query1.finance.yahoo.com/v8/finance/chart';
const FINNHUB_QUOTE = 'https://finnhub.io/api/v1/quote';

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

class RateLimiter {
  constructor(maxConcurrent = 5) { this.max = maxConcurrent; this.active = 0; this.queue = []; }
  async acquire() {
    if (this.active < this.max) { this.active++; return; }
    await new Promise(r => this.queue.push(r));
    this.active++;
  }
  release() { this.active--; const resolve = this.queue.shift(); if (resolve) resolve(); }
}

export async function fetchQuotes(symbols, options = {}) {
  const finnhubKey = options.finnhubKey || '';
  const retries = options.retries ?? DEFAULT_CONFIG.rate_limit.retries;
  const backoff = options.backoff_ms ?? DEFAULT_CONFIG.rate_limit.backoff_ms;
  const maxConcurrent = options.maxConcurrent ?? DEFAULT_CONFIG.rate_limit.max_concurrent;
  const benchmark = options.benchmark ?? DEFAULT_CONFIG.benchmark;

  const limiter = new RateLimiter(maxConcurrent);
  const allSymbols = [...symbols];
  if (benchmark && !allSymbols.includes(benchmark)) allSymbols.push(benchmark);

  const results = await Promise.all(allSymbols.map(async sym => {
    await limiter.acquire();
    try {
      for (let attempt = 0; attempt < retries; attempt++) {
        try {
          const yahoo = await fetchYahoo(sym);
          if (yahoo?.price) return yahoo;
          await sleep(backoff * (attempt + 1));
        } catch { await sleep(backoff * (attempt + 1)); }
      }
      const finn = await fetchFinnhub(sym, finnhubKey);
      if (finn?.price) return { symbol: sym, price: finn.price, currency: 'USD', prices: [], source: 'finnhub' };
    } finally {
      limiter.release();
    }
    return { symbol: sym, price: null, currency: 'USD', prices: [] };
  }));

  return results;
}

async function fetchYahoo(symbol) {
  const url = `${YAHOO_CHART}/${symbol}?interval=1d&range=6mo`;
  const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  const result = data.chart?.result?.[0];
  if (!result) throw new Error('No chart data');
  const meta = result.meta;
  const quotes = result.indicators?.quote?.[0];
  const closes = quotes?.close?.filter(v => v != null) ?? [];
  return {
    symbol,
    price: meta.regularMarketPrice ?? meta.previousClose ?? null,
    currency: meta.currency,
    previousClose: meta.previousClose,
    dayHigh: meta.regularMarketDayHigh,
    dayLow: meta.regularMarketDayLow,
    fiftyTwoWeekHigh: meta.fiftyTwoWeekHigh,
    fiftyTwoWeekLow: meta.fiftyTwoWeekLow,
    prices: closes,
    timestamps: result.timestamp ?? [],
    volumes: quotes?.volume ?? [],
    highs: quotes?.high ?? [],
    lows: quotes?.low ?? [],
    opens: quotes?.open ?? [],
    source: 'yahoo',
  };
}

async function fetchFinnhub(symbol, apiKey) {
  if (!apiKey) throw new Error('No API key');
  const url = `${FINNHUB_QUOTE}?symbol=${symbol}&token=${apiKey}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  return { symbol, price: data.c ?? null, currency: 'USD', source: 'finnhub' };
}
