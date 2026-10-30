#!/usr/bin/env node
import { UompClient } from '@uomp/sdk';
import { writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { mergeConfig } from './lib/config.js';
import { fetchQuotes } from './lib/market.js';
import { analyze } from './lib/analysis.js';
import { generateJSON, generateMarkdown, generateHTML } from './lib/report.js';

async function main() {
  const finnhubKey = process.env.FINNHUB_KEY || '';
  const lang = process.env.UOMP_LANG || 'zh';

  const uomp = UompClient.fromEnv();

  try {
    console.log(lang === 'en' ? 'Stock Analyst v1.0 started\n' : 'Stock Analyst v1.0 启动\n');

    const holdings = await uomp.memory.getByTag('portfolio:holdings');
    console.log(`${lang === 'en' ? 'Holdings' : '持仓'}: ${holdings.length} ${lang === 'en' ? 'positions' : '个标的'}`);

    const riskItems = await uomp.memory.getByTag('profile:risk');
    const risk = riskItems[0]?.value ?? {};
    console.log(`${lang === 'en' ? 'Risk' : '风险偏好'}: ${risk.risk_level ?? '?'}`);

    const symbols = [...new Set(holdings.map(h => h.value.symbol).filter(Boolean))];
    console.log(`\n${lang === 'en' ? 'Fetching quotes for' : '获取行情'}: ${symbols.join(', ')}`);
    const quotes = await fetchQuotes(symbols, { finnhubKey });
    const valid = quotes.filter(q => q?.price != null);
    console.log(`${lang === 'en' ? 'Received' : '收到'} ${valid.length}/${symbols.length} ${lang === 'en' ? 'quotes' : '条行情'}\n`);

    const config = mergeConfig();
    const analysis = analyze(holdings, risk, valid, config);

    if (!existsSync('./output')) await mkdir('./output', { recursive: true });
    const ts = Date.now();
    const reportZh = generateMarkdown(analysis, 'zh');
    const reportEn = generateMarkdown(analysis, 'en');
    await writeFile(`./output/stock-analysis-${ts}.md`, reportZh + '\n\n---\n\n' + reportEn, 'utf-8');
    await writeFile(`./output/stock-analysis-${ts}.json`, generateJSON(analysis), 'utf-8');
    await writeFile(`./output/stock-analysis-${ts}.html`, generateHTML(analysis), 'utf-8');

    console.log(`${lang === 'en' ? 'Reports' : '报告'}: output/stock-analysis-${ts}.(json|md|html)`);

    if (uomp.isRemote) {
      try {
        const id = await uomp.payload.upload(reportEn + '\n\n---\n\n' + reportZh);
        console.log(`\nPayload: ${id}`);
      } catch {}
    }

    try {
      const result = await uomp.session.submitDeletionProof();
      console.log(`Deletion proof: ${result.deletion_proof_id}`);
    } catch {}

    console.log(lang === 'en' ? '\n═══ Complete ═══' : '\n═══ 完成 ═══');
    console.log(`P&L: ${analysis.totalPnl} (${analysis.totalPnlPct}%) | HHI: ${analysis.hhi} | Sharpe: ${analysis.portfolioSharpe ?? '-'} | Signals: ${analysis.signals.length}`);
  } catch (error) {
    console.error(lang === 'en' ? 'Error:' : '错误:', error.message);
    process.exit(1);
  }
}

main();
