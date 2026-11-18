//! Provider model pricing table and overflow-safe micro-USD cost accounting.
//!
//! All monetary values are stored in integer `micro_usd` (`1 USD = 1_000_000 micro_usd`) to
//! avoid floating-point drift across concurrent `AtomicU64` budget reservations and settlements.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pricing rates expressed in micro-USD per 1,000,000 tokens (`$1.00 = 1_000_000 micro_usd`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRate {
    pub input_micro_usd_per_mtok: u64,
    pub output_micro_usd_per_mtok: u64,
    pub cached_input_micro_usd_per_mtok: u64,
}

impl Default for ModelRate {
    fn default() -> Self {
        // Conservative default fallback ($3 / MTok input, $15 / MTok output, $0.30 / MTok cached).
        Self {
            input_micro_usd_per_mtok: 3_000_000,
            output_micro_usd_per_mtok: 15_000_000,
            cached_input_micro_usd_per_mtok: 300_000,
        }
    }
}

/// Configurable model pricing registry with built-in defaults and per-model overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelPricingTable {
    #[serde(default)]
    pub overrides: HashMap<String, ModelRate>,
}

impl ModelPricingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_overrides(overrides: HashMap<String, ModelRate>) -> Self {
        Self { overrides }
    }

    /// Resolves the active `ModelRate` for `model` (checks exact case-insensitive override first,
    /// then built-in provider family prefixes, then `ModelRate::default()`).
    pub fn rate_for(&self, model: &str) -> ModelRate {
        let trimmed = model.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some((_, rate)) = self
            .overrides
            .iter()
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(trimmed))
        {
            return *rate;
        }
        // Check longer override substring matches deterministically as fallback.
        let mut best_override: Option<(usize, ModelRate)> = None;
        for (pattern, rate) in &self.overrides {
            let p_lower = pattern.trim().to_ascii_lowercase();
            if !p_lower.is_empty()
                && lower.contains(&p_lower)
                && best_override
                    .as_ref()
                    .is_none_or(|(best_len, _)| p_lower.len() > *best_len)
            {
                best_override = Some((p_lower.len(), *rate));
            }
        }
        if let Some((_, rate)) = best_override {
            return rate;
        }

        Self::builtin_rate_for(&lower)
    }

    fn builtin_rate_for(lower: &str) -> ModelRate {
        if lower.contains("claude-opus") || lower.contains("opus-4") {
            ModelRate {
                input_micro_usd_per_mtok: 15_000_000,
                output_micro_usd_per_mtok: 75_000_000,
                cached_input_micro_usd_per_mtok: 1_500_000,
            }
        } else if lower.contains("claude-sonnet") || lower.contains("sonnet-4") {
            ModelRate {
                input_micro_usd_per_mtok: 3_000_000,
                output_micro_usd_per_mtok: 15_000_000,
                cached_input_micro_usd_per_mtok: 300_000,
            }
        } else if lower.contains("claude-haiku") || lower.contains("haiku-") {
            ModelRate {
                input_micro_usd_per_mtok: 800_000,
                output_micro_usd_per_mtok: 4_000_000,
                cached_input_micro_usd_per_mtok: 80_000,
            }
        } else if lower.contains("o4-mini") {
            ModelRate {
                input_micro_usd_per_mtok: 1_100_000,
                output_micro_usd_per_mtok: 4_400_000,
                cached_input_micro_usd_per_mtok: 275_000,
            }
        } else if lower.contains("o3-mini") {
            ModelRate {
                input_micro_usd_per_mtok: 1_100_000,
                output_micro_usd_per_mtok: 4_400_000,
                cached_input_micro_usd_per_mtok: 550_000,
            }
        } else if lower.contains("o3") {
            ModelRate {
                input_micro_usd_per_mtok: 2_000_000,
                output_micro_usd_per_mtok: 8_000_000,
                cached_input_micro_usd_per_mtok: 500_000,
            }
        } else if lower.contains("gpt-5") {
            ModelRate {
                input_micro_usd_per_mtok: 1_250_000,
                output_micro_usd_per_mtok: 10_000_000,
                cached_input_micro_usd_per_mtok: 125_000,
            }
        } else if lower.contains("gpt-4.1-mini") || lower.contains("gpt-4o-mini") {
            ModelRate {
                input_micro_usd_per_mtok: 400_000,
                output_micro_usd_per_mtok: 1_600_000,
                cached_input_micro_usd_per_mtok: 100_000,
            }
        } else if lower.contains("gpt-4.1") || lower.contains("gpt-4o") {
            ModelRate {
                input_micro_usd_per_mtok: 2_500_000,
                output_micro_usd_per_mtok: 10_000_000,
                cached_input_micro_usd_per_mtok: 1_250_000,
            }
        } else if lower.contains("gemini-2.5-flash") || lower.contains("gemini-flash") {
            ModelRate {
                input_micro_usd_per_mtok: 300_000,
                output_micro_usd_per_mtok: 2_500_000,
                cached_input_micro_usd_per_mtok: 75_000,
            }
        } else if lower.contains("gemini-2.5-pro") || lower.contains("gemini-3") {
            ModelRate {
                input_micro_usd_per_mtok: 1_250_000,
                output_micro_usd_per_mtok: 10_000_000,
                cached_input_micro_usd_per_mtok: 312_500,
            }
        } else if lower.contains("deepseek") {
            ModelRate {
                input_micro_usd_per_mtok: 280_000,
                output_micro_usd_per_mtok: 1_100_000,
                cached_input_micro_usd_per_mtok: 70_000,
            }
        } else {
            ModelRate::default()
        }
    }

    /// Computes ceiling cost in `micro_usd` using widening `u128` arithmetic.
    pub fn compute_cost_micro_usd(
        &self,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
    ) -> u64 {
        let rate = self.rate_for(model);
        let in_scaled = u128::from(input_tokens) * u128::from(rate.input_micro_usd_per_mtok);
        let out_scaled = u128::from(output_tokens) * u128::from(rate.output_micro_usd_per_mtok);
        let cached_scaled =
            u128::from(cached_input_tokens) * u128::from(rate.cached_input_micro_usd_per_mtok);
        let total = in_scaled
            .saturating_add(out_scaled)
            .saturating_add(cached_scaled);
        if total == 0 {
            0
        } else {
            let quotient = total / 1_000_000;
            let remainder = total % 1_000_000;
            let micro = quotient.saturating_add(if remainder == 0 { 0 } else { 1 });
            u64::try_from(micro).unwrap_or(u64::MAX)
        }
    }

    /// Conservative pre-flight cost reservation for estimated input tokens before streaming begins.
    pub fn estimate_preflight_cost_micro_usd(&self, model: &str, estimated_input_tokens: u64) -> u64 {
        self.compute_cost_micro_usd(model, estimated_input_tokens, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pricing_table_resolves_builtin_overrides_and_avoids_overflow() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "custom-test-model".to_string(),
            ModelRate {
                input_micro_usd_per_mtok: 2_000_000,
                output_micro_usd_per_mtok: 8_000_000,
                cached_input_micro_usd_per_mtok: 200_000,
            },
        );
        let table = ModelPricingTable::with_overrides(overrides);
        assert_eq!(
            table.rate_for("claude-opus-4-6").output_micro_usd_per_mtok,
            75_000_000
        );
        assert_eq!(
            table.rate_for("gpt-4o-mini").input_micro_usd_per_mtok,
            400_000
        );
        assert_eq!(
            table.compute_cost_micro_usd("custom-test-model", 1_000_000, 500_000, 500_000),
            2_000_000 + 4_000_000 + 100_000
        );
        // $2 / MTok => 2 micro_usd per single input token; $0.20 / MTok cached => rounds up to 1.
        assert_eq!(
            table.compute_cost_micro_usd("custom-test-model", 1, 0, 0),
            2
        );
        assert_eq!(
            table.compute_cost_micro_usd("custom-test-model", 0, 0, 1),
            1
        );
        assert_eq!(table.compute_cost_micro_usd("custom-test-model", 0, 0, 0), 0);
        // Very large token counts saturate cleanly without panic.
        let huge = table.compute_cost_micro_usd("claude-opus-4-6", u64::MAX, u64::MAX, 0);
        assert_eq!(huge, u64::MAX);
    }
}
