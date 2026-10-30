export function generateJSON(analysis) {
  return JSON.stringify({
    ...analysis,
    rows: analysis.rows.map(r => ({
      symbol: r.symbol, name: r.name, quantity: r.quantity,
      cost_basis: r.costBasis, current_price: +r.currentPrice.toFixed(2),
      current_value: +r.currentValue.toFixed(2),
      pnl: +r.pnl.toFixed(2), pnl_pct: +r.pnlPct.toFixed(2),
      weight_pct: +r.weight.toFixed(2), sector: r.sector,
      volatility_annual: r.volatility != null ? +r.volatility.toFixed(2) : null,
      sharpe: r.sharpe != null ? +r.sharpe.toFixed(3) : null,
      var95: r.var95 != null ? +r.var95.toFixed(4) : null,
      beta: r.beta != null ? +r.beta.toFixed(2) : null,
      alpha_daily: r.alpha != null ? +r.alpha.toFixed(6) : null,
      max_drawdown_pct: +(r.maxDrawdown?.maxDD ?? 0 * 100).toFixed(2),
      rsi14: r.rsi14 != null ? +r.rsi14.toFixed(1) : null,
      macd: r.macd ? { macd: +r.macd.macd.toFixed(4), signal: +r.macd.signal.toFixed(4), histogram: +r.macd.histogram.toFixed(4) } : null,
      ma50: r.ma50 != null ? +r.ma50.toFixed(2) : null,
      ma200: r.ma200 != null ? +r.ma200.toFixed(2) : null,
    })),
  }, null, 2);
}

export function generateMarkdown(analysis, lang = 'zh') {
  const en = lang === 'en';
  const l = [];

  l.push(en ? '# Portfolio Analysis Report' : '# 持仓分析报告');
  l.push('');
  l.push(`${en ? 'Generated' : '生成时间'}: ${analysis.timestamp}`);
  l.push(`${en ? 'Risk' : '风险'}: ${analysis.riskLevel} | ${en ? 'Horizon' : '周期'}: ${analysis.investmentHorizon}`);
  if (analysis.benchmarkReturn) {
    l.push(`${en ? 'Benchmark' : '基准'}: ${analysis.benchmarkReturn.symbol} @ ${analysis.benchmarkReturn.price} (vol: ${analysis.benchmarkReturn.annualVol}%)`);
  }
  l.push('');

  // Holdings
  l.push(en ? '## Holdings' : '## 持仓明细');
  l.push('');
  l.push(en
    ? '| Symbol | Name | Qty | Cost | Price | Value | P&L | P&L% | Wgt% | Vol% | Beta | RSI | Sector |'
    : '| 标的 | 名称 | 数量 | 成本 | 当前价 | 市值 | 盈亏 | 盈亏% | 权重% | 波动率% | Beta | RSI | 行业 |');
  l.push('|--------|------|-----|------|-------|-------|-----|------|------|--------|------|-----|--------|');
  for (const r of analysis.rows) {
    const vol = r.volatility?.toFixed(1) ?? '-';
    const beta = r.beta?.toFixed(2) ?? '-';
    const rsi = r.rsi14?.toFixed(1) ?? '-';
    l.push(`| ${r.symbol} | ${r.name} | ${r.quantity} | ${r.costBasis.toFixed(2)} | ${r.currentPrice.toFixed(2)} | ${r.currentValue.toFixed(2)} | ${r.pnl.toFixed(2)} | ${r.pnlPct.toFixed(2)}% | ${r.weight.toFixed(2)}% | ${vol} | ${beta} | ${rsi} | ${r.sector} |`);
  }

  // Summary
  l.push('');
  l.push(en ? '## Summary' : '## 汇总');
  l.push(`- ${en ? 'Total Cost' : '总成本'}: ${analysis.totalCost}`);
  l.push(`- ${en ? 'Total Value' : '总市值'}: ${analysis.totalValue}`);
  l.push(`- ${en ? 'Total P&L' : '总盈亏'}: ${analysis.totalPnl} (${analysis.totalPnlPct}%)`);
  l.push(`- HHI: ${analysis.hhi}${analysis.hhi > 2500 ? ' ⚠' : ''}`);
  if (analysis.portfolioVolatility != null) l.push(`- ${en ? 'Portfolio Vol' : '组合波动率'}: ${analysis.portfolioVolatility}%`);
  if (analysis.portfolioSharpe != null) l.push(`- ${en ? 'Portfolio Sharpe' : '组合 Sharpe'}: ${analysis.portfolioSharpe}`);

  // Sector
  l.push('');
  l.push(en ? '## Sector Allocation' : '## 行业分布');
  for (const [sec, pct] of Object.entries(analysis.sector.percentages).sort((a, b) => b[1] - a[1])) {
    const dev = analysis.sector.deviations[sec];
    const devStr = dev != null ? ` (${en ? 'target' : '目标'}: ${analysis.targetAllocation?.[sec]}%, ${dev >= 0 ? '+' : ''}${dev.toFixed(1)}%)` : '';
    l.push(`- ${sec}: ${pct.toFixed(1)}%${devStr}`);
  }

  // Correlation
  if (analysis.correlationMatrix.length > 1) {
    l.push('');
    l.push(en ? '## Correlation Matrix' : '## 相关矩阵');
    l.push('');
    l.push('| ' + analysis.correlationMatrix.map(c => c.symbol).join(' | ') + ' |');
    l.push('|' + analysis.correlationMatrix.map(() => '------').join('|') + '|');
    for (const cr of analysis.correlationMatrix) {
      l.push('| ' + cr.correlations.map(v => v != null ? v.toFixed(2) : '-').join(' | ') + ' |');
    }
  }

  // Signals
  if (analysis.signals.length > 0) {
    l.push('');
    l.push(en ? '## Signals' : '## 交易信号');
    for (const s of analysis.signals) {
      l.push(`- ${s.type.includes('stop') ? '🔴' : '🟢'} ${s.msg}`);
    }
  }

  // Drawdown
  if (analysis.drawdownWarnings.length > 0) {
    l.push('');
    l.push(en ? '## Drawdown Alerts' : '## 回撤告警');
    for (const d of analysis.drawdownWarnings) {
      l.push(`- ${d.symbol}: ${d.drawdown.toFixed(1)}% (limit: ${d.limit}%)`);
    }
  }

  // Rebalance
  if (analysis.rebalance.length > 0) {
    l.push('');
    l.push(en ? '## Rebalance Suggestions' : '## 再平衡建议');
    for (const rb of analysis.rebalance) {
      const act = rb.action === 'sell' ? (en ? 'Sell' : '卖出') : (en ? 'Buy' : '买入');
      l.push(`- **${rb.sector}**: ${act} $${rb.amount} (${rb.deviation_pct}%) → ${rb.suggestions.join(', ')}`);
    }
  }

  // Scenarios
  l.push('');
  l.push(en ? '## Scenario Analysis' : '## 情景分析');
  l.push('');
  l.push(en ? '| Scenario | Portfolio Value | P&L | P&L% |' : '| 情景 | 组合价值 | 盈亏 | 盈亏% |');
  l.push('|----------|-----------------|-----|------|');
  for (const sc of analysis.scenarios) {
    l.push(`| ${sc.scenario} | ${sc.portfolio_value} | ${sc.pnl} | ${sc.pnl_pct}% |`);
  }

  l.push('');
  l.push(en
    ? '> Generated by UOMP Stock Analyst. No portfolio data uploaded to external services.'
    : '> UOMP Stock Analyst 生成。未向外部服务上传持仓数据。');

  return l.join('\n');
}

export function generateHTML(analysis) {
  const rowHTML = analysis.rows.map(r => `
    <tr>
      <td>${r.symbol}</td><td>${r.name}</td><td>${r.quantity}</td>
      <td>${r.costBasis.toFixed(2)}</td><td>${r.currentPrice.toFixed(2)}</td>
      <td>${r.currentValue.toFixed(2)}</td>
      <td class="${r.pnl > 0 ? 'pos' : 'neg'}">${r.pnl.toFixed(2)}</td>
      <td>${r.pnlPct.toFixed(2)}%</td><td>${r.weight.toFixed(2)}%</td>
      <td>${r.volatility?.toFixed(1) ?? '-'}</td>
      <td>${r.beta?.toFixed(2) ?? '-'}</td>
      <td>${r.rsi14?.toFixed(1) ?? '-'}</td>
      <td>${r.sector}</td>
    </tr>`).join('');

  const sectorHTML = Object.entries(analysis.sector.percentages)
    .sort((a, b) => b[1] - a[1])
    .map(([sec, pct]) => {
      const dev = analysis.sector.deviations[sec];
      return `<li>${sec}: ${pct.toFixed(1)}%${dev != null ? ` (target ${analysis.targetAllocation?.[sec]}%, ${dev >= 0 ? '+' : ''}${dev.toFixed(1)}%)` : ''} <div class="bar"><div class="fill" style="width:${Math.min(pct, 100)}%"></div></div></li>`;
    }).join('');

  const signalHTML = analysis.signals.map(s => `<li class="${s.type.includes('stop') ? 'alert' : 'good'}">${s.msg}</li>`).join('');
  const rebalanceHTML = analysis.rebalance.map(r => `<li>${r.sector}: <b>${r.action}</b> $${r.amount} (${r.deviation_pct}%) → ${r.suggestions.join(', ')}</li>`).join('');
  const scenarioHTML = analysis.scenarios.map(s => `
    <tr><td>${s.scenario}</td><td>${s.portfolio_value}</td><td class="${s.pnl >= 0 ? 'pos' : 'neg'}">${s.pnl}</td><td>${s.pnl_pct}%</td></tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>UOMP Stock Analyst Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0A0A0A; color: #E5E7EB; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 2rem; margin-bottom: .5rem; color: #fff; }
  .meta { color: #9CA3AF; margin-bottom: 2rem; font-size: .9rem; }
  h2 { font-size: 1.3rem; margin: 2rem 0 1rem; color: #F9FAFB; border-bottom: 1px solid #1F2937; padding-bottom: .5rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .85rem; }
  th, td { padding: .5rem .75rem; text-align: right; border-bottom: 1px solid #1F2937; }
  th { background: #111; font-weight: 600; color: #D1D5DB; }
  td:first-child, th:first-child { text-align: left; }
  td:nth-child(2), th:nth-child(2) { text-align: left; }
  .pos { color: #34D399; } .neg { color: #F87171; }
  ul { list-style: none; padding: 0; }
  li { padding: .4rem 0; border-bottom: 1px solid #1A1A1A; }
  .alert { color: #F87171; } .good { color: #34D399; }
  .bar { background: #1F2937; height: 8px; border-radius: 4px; margin-top: .3rem; }
  .fill { background: #3B82F6; height: 8px; border-radius: 4px; min-width: 2px; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }
  .badge-warn { background: #78350F; color: #FBBF24; }
  .badge-ok { background: #064E3B; color: #34D399; }
  .badge-danger { background: #7F1D1D; color: #F87171; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #1F2937; color: #6B7280; font-size: .8rem; }
</style>
</head>
<body>
<div class="container">
<h1>Portfolio Analysis Report</h1>
<div class="meta">
  ${analysis.timestamp} &nbsp;|&nbsp; Risk: ${analysis.riskLevel} &nbsp;|&nbsp; Horizon: ${analysis.investmentHorizon}
  &nbsp;|&nbsp; Benchmark: ${analysis.benchmark} @ ${analysis.benchmarkReturn?.price ?? '-'}
</div>

<h2>Holdings</h2>
<table><thead><tr>
  <th>Sym</th><th>Name</th><th>Qty</th><th>Cost</th><th>Price</th><th>Value</th><th>P&amp;L</th><th>P&amp;L%</th><th>Wgt%</th><th>Vol%</th><th>Beta</th><th>RSI</th><th>Sector</th>
</tr></thead><tbody>${rowHTML}</tbody></table>

<h2>Summary</h2>
<ul>
  <li>Total Cost: <b>$${analysis.totalCost.toLocaleString()}</b></li>
  <li>Total Value: <b>$${analysis.totalValue.toLocaleString()}</b></li>
  <li>Total P&amp;L: <b class="${analysis.totalPnl > 0 ? 'pos' : 'neg'}">$${analysis.totalPnl.toLocaleString()} (${analysis.totalPnlPct}%)</b></li>
  <li>HHI: ${analysis.hhi} ${analysis.hhi > 2500 ? '<span class="badge badge-warn">High</span>' : '<span class="badge badge-ok">OK</span>'}</li>
  ${analysis.portfolioVolatility != null ? `<li>Portfolio Volatility: ${analysis.portfolioVolatility}%</li>` : ''}
  ${analysis.portfolioSharpe != null ? `<li>Sharpe Ratio: ${analysis.portfolioSharpe}</li>` : ''}
</ul>

<h2>Sector Allocation</h2>
<ul>${sectorHTML}</ul>

${analysis.signals.length > 0 ? `<h2>Signals</h2><ul>${signalHTML}</ul>` : ''}
${analysis.drawdownWarnings.length > 0 ? `<h2>Drawdown Alerts</h2><ul>${analysis.drawdownWarnings.map(d => `<li class="alert">${d.symbol}: ${d.drawdown.toFixed(1)}% (limit: ${d.limit}%)</li>`).join('')}</ul>` : ''}
${analysis.rebalance.length > 0 ? `<h2>Rebalance Suggestions</h2><ul>${rebalanceHTML}</ul>` : ''}

<h2>Scenario Analysis</h2>
<table><thead><tr><th>Scenario</th><th>Portfolio Value</th><th>P&amp;L</th><th>P&amp;L%</th></tr></thead><tbody>${scenarioHTML}</tbody></table>

<div class="footer">Generated by UOMP Stock Analyst · No portfolio data was uploaded to external services · Market data from public APIs</div>
</div>
</body>
</html>`;
}
