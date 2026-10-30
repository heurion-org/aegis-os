export const DEFAULT_CONFIG = {
  thresholds: {
    stop_loss_pct: 15,
    take_profit_pct: 50,
    high_concentration_hhi: 2500,
    critical_concentration_hhi: 4000,
    low_sharpe: 0.5,
    high_volatility: 30,
    rsi_overbought: 70,
    rsi_oversold: 30,
    var_confidence: 0.95,
  },
  benchmark: 'SPY',
  risk_free_rate: 0.03,
  scenario_shocks: [-0.05, -0.10, -0.20, -0.30],
  rate_limit: { max_concurrent: 5, retries: 3, backoff_ms: 1000 },
  report: { include_html: true, include_json: true, include_markdown: true },
  languages: ['zh', 'en'],
};

export function mergeConfig(userConfig = {}) {
  const result = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  for (const [key, val] of Object.entries(userConfig)) {
    if (result[key] && typeof val === 'object' && !Array.isArray(val)) {
      Object.assign(result[key], val);
    } else {
      result[key] = val;
    }
  }
  return result;
}
