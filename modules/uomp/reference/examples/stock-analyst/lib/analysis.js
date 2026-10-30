// ── Statistics ───────────────────────────────────────────────────

export function computeReturnSeries(prices) {
  if (prices.length < 2) return [];
  const r = [];
  for (let i = 1; i < prices.length; i++) r.push((prices[i] - prices[i - 1]) / prices[i - 1]);
  return r;
}

function sum(arr) { return arr.reduce((a, b) => a + b, 0); }
function mean(arr) { return arr.length === 0 ? 0 : sum(arr) / arr.length; }

export function stddev(arr, sample = true) {
  if (arr.length < (sample ? 2 : 1)) return 0;
  const m = mean(arr);
  return Math.sqrt(sum(arr.map(v => (v - m) ** 2)) / (arr.length - (sample ? 1 : 0)));
}

export function covariance(a, b) {
  if (!a.length || a.length !== b.length) return 0;
  const ma = mean(a), mb = mean(b);
  return sum(a.map((ai, i) => (ai - ma) * (b[i] - mb))) / (a.length - 1);
}

export function correlation(a, b) {
  const sa = stddev(a), sb = stddev(b);
  if (sa === 0 || sb === 0) return null;
  return covariance(a, b) / (sa * sb);
}

function quantile(arr, q) {
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = q * (sorted.length - 1);
  const lo = Math.floor(idx), hi = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  return sorted[lo] + (idx - lo) * (sorted[hi] - sorted[lo]);
}

// ── Annualized metrics ───────────────────────────────────────────

export function annualVol(prices) {
  const rets = computeReturnSeries(prices);
  return rets.length < 2 ? null : stddev(rets) * Math.sqrt(252);
}

export function sharpeRatio(prices, riskFreeRate = 0.03) {
  const rets = computeReturnSeries(prices);
  if (rets.length < 2) return null;
  const avg = mean(rets), vol = stddev(rets);
  if (vol === 0) return null;
  return ((avg - riskFreeRate / 252) / vol) * Math.sqrt(252);
}

export function valueAtRisk(prices, confidence = 0.95) {
  const rets = computeReturnSeries(prices);
  if (rets.length < 10) return null;
  return quantile(rets, 1 - confidence);
}

export function maxDrawdown(prices) {
  if (prices.length < 2) return { maxDD: 0, peakIdx: 0, troughIdx: 0, startIdx: 0, endIdx: 0 };
  let peak = prices[0], peakIdx = 0, maxDD = 0, start = 0, end = 0;
  for (let i = 1; i < prices.length; i++) {
    if (prices[i] > peak) { peak = prices[i]; peakIdx = i; continue; }
    const dd = (prices[i] - peak) / peak;
    if (dd < maxDD) { maxDD = dd; start = peakIdx; end = i; }
  }
  return { maxDD, peakIdx: start, troughIdx: end };
}

// ── Beta / Alpha ─────────────────────────────────────────────────

export function computeBeta(stockReturns, marketReturns) {
  if (!stockReturns.length || !marketReturns.length) return null;
  const len = Math.min(stockReturns.length, marketReturns.length);
  const cov = covariance(stockReturns.slice(-len), marketReturns.slice(-len));
  const mV = stddev(marketReturns.slice(-len)) ** 2;
  return mV === 0 ? null : cov / mV;
}

export function computeAlpha(stockReturns, marketReturns, riskFreeRate = 0.03) {
  const beta = computeBeta(stockReturns, marketReturns);
  if (beta === null) return null;
  const dailyRf = riskFreeRate / 252;
  return (mean(stockReturns) - dailyRf) - beta * (mean(marketReturns) - dailyRf);
}

// ── Technical Indicators ─────────────────────────────────────────

export function computeRSI(prices, period = 14) {
  if (prices.length < period + 1) return null;
  const changes = [];
  for (let i = 1; i < prices.length; i++) changes.push(prices[i] - prices[i - 1]);
  let avgGain = sum(changes.slice(0, period).filter(c => c > 0)) / period;
  let avgLoss = -sum(changes.slice(0, period).filter(c => c < 0)) / period;
  for (let i = period; i < changes.length; i++) {
    avgGain = (avgGain * (period - 1) + (changes[i] > 0 ? changes[i] : 0)) / period;
    avgLoss = (avgLoss * (period - 1) + (changes[i] < 0 ? -changes[i] : 0)) / period;
  }
  if (avgLoss === 0) return 100;
  return 100 - (100 / (1 + avgGain / avgLoss));
}

export function computeMACD(prices, fast = 12, slow = 26, signal = 9) {
  if (prices.length < slow + signal) return null;
  const ema = (data, period) => {
    const k = 2 / (period + 1);
    let e = data[0];
    for (let i = 1; i < data.length; i++) e = data[i] * k + e * (1 - k);
    return e;
  };
  const fastEMA = [], slowEMA = [], macdLine = [];
  const end = prices.length;
  for (let i = slow; i < end; i++) {
    const slice = prices.slice(0, i + 1);
    fastEMA.push(ema(slice.slice(-fast), fast));
    slowEMA.push(ema(slice, slow));
    macdLine.push(fastEMA[fastEMA.length - 1] - slowEMA[slowEMA.length - 1]);
  }
  const signalLine = macdLine.length >= signal ? ema(macdLine, signal) : 0;
  const latestMacd = macdLine[macdLine.length - 1] ?? 0;
  const latestSignal = signalLine;
  return { macd: latestMacd, signal: latestSignal, histogram: latestMacd - latestSignal };
}

export function computeMA(prices, period) {
  if (prices.length < period) return null;
  return mean(prices.slice(-period));
}

// ── Portfolio Analysis ───────────────────────────────────────────

export function analyze(holdings, risk, quotes, config) {
  const cfg = config.thresholds;
  const benchSym = config.benchmark || 'SPY';
  const benchmark = quotes.find(q => q?.symbol === benchSym && q?.prices?.length > 10);
  const benchReturns = benchmark ? computeReturnSeries(benchmark.prices) : [];

  // Per-holding metrics
  const rows = [];
  let totalCost = 0, totalValue = 0;
  const allReturns = [];

  for (const item of holdings) {
    const h = item.value;
    const qty = parseFloat(h.quantity);
    const costBasis = parseFloat(h.cost_basis);
    const q = quotes.find(qa => qa?.symbol === h.symbol);
    const price = q?.price ?? (parseFloat(h.market_value) / qty);
    const curVal = price * qty;
    const costVal = costBasis * qty;
    const pnl = curVal - costVal;
    const pnlPct = costVal > 0 ? (pnl / costVal) * 100 : 0;
    totalCost += costVal;
    totalValue += curVal;

    const prices = q?.prices ?? [];
    const rets = computeReturnSeries(prices);
    allReturns.push(rets);

    rows.push({
      symbol: h.symbol, name: h.name ?? h.symbol,
      quantity: qty, costBasis, currentPrice: price,
      currentValue: curVal, pnl, pnlPct, weight: 0,
      sector: h.sector ?? 'Unknown',
      prices, returns: rets,
      volatility: annualVol(prices),
      sharpe: sharpeRatio(prices, config.risk_free_rate),
      var95: valueAtRisk(prices, cfg.var_confidence),
      maxDrawdown: maxDrawdown(prices),
      rsi14: computeRSI(prices, 14),
      macd: computeMACD(prices),
      ma50: computeMA(prices, 50),
      ma200: computeMA(prices, 200),
    });
  }

  // Weights
  for (const r of rows) r.weight = totalValue > 0 ? (r.currentValue / totalValue) * 100 : 0;

  // Market proxy returns
  const marketProxy = benchmark?.prices?.length > 10
    ? benchReturns
    : aggregateMarketProxy(allReturns);
  const mpLen = Math.min(...allReturns.filter(r => r.length > 0).map(r => r.length), marketProxy.length);

  for (const r of rows) {
    if (r.returns.length >= 2 && marketProxy.length >= 2) {
      r.beta = computeBeta(r.returns, marketProxy);
      r.alpha = computeAlpha(r.returns, marketProxy, config.risk_free_rate);
    }
  }

  // Sector allocation
  const sectorMap = {}, sectorPct = {};
  for (const r of rows) { sectorMap[r.sector] = (sectorMap[r.sector] ?? 0) + r.currentValue; }
  for (const [k, v] of Object.entries(sectorMap)) sectorPct[k] = totalValue > 0 ? (v / totalValue) * 100 : 0;

  const sectorDevs = {};
  if (risk?.target_allocation) {
    for (const [sec, target] of Object.entries(risk.target_allocation)) {
      sectorDevs[sec] = (sectorPct[sec] ?? 0) - target;
    }
  }

  // HHI
  const hhi = rows.reduce((s, r) => s + r.weight * r.weight, 0);

  // Correlation matrix
  const correlationMatrix = [];
  for (let i = 0; i < rows.length; i++) {
    const row = [];
    for (let j = 0; j < rows.length; j++) {
      if (i === j) { row.push(1); continue; }
      const minLen = Math.min(rows[i].returns.length, rows[j].returns.length);
      if (minLen < 2) { row.push(null); continue; }
      row.push(+(correlation(rows[i].returns.slice(-minLen), rows[j].returns.slice(-minLen)) ?? 0).toFixed(3));
    }
    correlationMatrix.push({ symbol: rows[i].symbol, correlations: row });
  }

  // Portfolio volatility
  let portVol = null;
  if (rows.every(r => r.volatility != null)) {
    let v = 0;
    for (let i = 0; i < rows.length; i++) {
      for (let j = 0; j < rows.length; j++) {
        const corr = i === j ? 1 : (correlationMatrix[i].correlations[j] ?? 0.3);
        v += (rows[i].weight / 100) * (rows[j].weight / 100) * (rows[i].volatility / 100) * (rows[j].volatility / 100) * corr;
      }
    }
    portVol = Math.sqrt(Math.max(0, v)) * 100;
  }

  // Portfolio Sharpe
  let portSharpe = null;
  if (marketProxy.length > 2) {
    const portRets = [];
    for (let i = 0; i < mpLen; i++) {
      let r = 0;
      for (const row of rows) {
        if (i < row.returns.length) r += (row.weight / 100) * row.returns[i];
      }
      portRets.push(r);
    }
    if (portRets.length > 2) {
      const avg = mean(portRets), vol = stddev(portRets);
      portSharpe = vol === 0 ? null : ((avg - config.risk_free_rate / 252) / vol) * Math.sqrt(252);
    }
  }

  // Signals
  const signals = [], drawdownWarnings = [];
  for (const r of rows) {
    if (risk?.stop_loss_pct && r.pnlPct <= -risk.stop_loss_pct) {
      signals.push({ type: 'stop_loss', symbol: r.symbol,
        msg: `${r.symbol} ${r.pnlPct.toFixed(1)}% (SL: ${risk.stop_loss_pct}%)` });
    }
    if (risk?.take_profit_pct && r.pnlPct >= risk.take_profit_pct) {
      signals.push({ type: 'take_profit', symbol: r.symbol,
        msg: `${r.symbol} ${r.pnlPct.toFixed(1)}% (TP: ${risk.take_profit_pct}%)` });
    }
    if (risk?.max_drawdown != null) {
      const dd = ((r.currentPrice - r.costBasis) / r.costBasis) * 100;
      if (dd < -risk.max_drawdown * 100) {
        drawdownWarnings.push({ symbol: r.symbol, drawdown: dd, limit: -risk.max_drawdown * 100 });
      }
    }
    if (r.rsi14 != null && r.rsi14 > cfg.rsi_overbought) {
      signals.push({ type: 'rsi_overbought', symbol: r.symbol, msg: `${r.symbol} RSI ${r.rsi14.toFixed(1)} (overbought)` });
    }
    if (r.rsi14 != null && r.rsi14 < cfg.rsi_oversold) {
      signals.push({ type: 'rsi_oversold', symbol: r.symbol, msg: `${r.symbol} RSI ${r.rsi14.toFixed(1)} (oversold)` });
    }
  }

  // Rebalance suggestions
  const rebalance = [];
  if (risk?.target_allocation) {
    for (const [sec, target] of Object.entries(risk.target_allocation)) {
      const actual = sectorPct[sec] ?? 0;
      const diff = actual - target;
      if (Math.abs(diff) > 3) {
        const action = diff > 0 ? 'sell' : 'buy';
        const amount = Math.abs(diff) / 100 * totalValue;
        const suggestions = rows
          .filter(r => (action === 'sell' ? r.sector === sec : r.sector !== sec && !['Cash', 'Unknown'].includes(r.sector)))
          .sort((a, b) => action === 'sell' ? a.pnlPct - b.pnlPct : b.pnlPct - a.pnlPct)
          .slice(0, 3)
          .map(r => r.symbol);
        rebalance.push({ sector: sec, action, deviation_pct: +diff.toFixed(1), amount: +amount.toFixed(2), suggestions });
      }
    }
  }

  // Scenario analysis
  const scenarios = [];
  for (const shock of config.scenario_shocks) {
    const shockedValue = totalValue * (1 + shock);
    const shockedPnl = shockedValue - totalCost;
    const shockedPnlPct = totalCost > 0 ? (shockedPnl / totalCost) * 100 : 0;
    scenarios.push({
      scenario: `Market ${(shock * 100).toFixed(0)}%`,
      shock,
      portfolio_value: +shockedValue.toFixed(2),
      pnl: +shockedPnl.toFixed(2),
      pnl_pct: +shockedPnlPct.toFixed(2),
    });
  }

  return {
    rows,
    totalCost: +totalCost.toFixed(2),
    totalValue: +totalValue.toFixed(2),
    totalPnl: +(totalValue - totalCost).toFixed(2),
    totalPnlPct: totalCost > 0 ? +((totalValue - totalCost) / totalCost * 100).toFixed(2) : 0,
    hhi: +hhi.toFixed(1),
    sector: { percentages: sectorPct, deviations: sectorDevs },
    correlationMatrix,
    portfolioVolatility: portVol != null ? +portVol.toFixed(2) : null,
    portfolioSharpe: portSharpe != null ? +portSharpe.toFixed(3) : null,
    signals,
    drawdownWarnings,
    rebalance,
    scenarios,
    riskLevel: risk?.risk_level ?? 'unknown',
    investmentHorizon: risk?.investment_horizon ?? 'unknown',
    targetAllocation: risk?.target_allocation ?? null,
    benchmark: benchSym,
    benchmarkReturn: benchmark ? {
      symbol: benchSym,
      price: benchmark.price,
      annualVol: annualVol(benchmark.prices) != null ? +(annualVol(benchmark.prices) * 100).toFixed(2) : null,
    } : null,
    timestamp: new Date().toISOString(),
  };
}

function aggregateMarketProxy(allReturns) {
  const maxLen = Math.max(0, ...allReturns.map(r => r.length));
  const proxy = [];
  for (let i = 0; i < maxLen; i++) {
    let s = 0, c = 0;
    for (const rets of allReturns) { if (i < rets.length) { s += rets[i]; c++; } }
    proxy.push(c > 0 ? s / c : 0);
  }
  return proxy;
}
