// SPDX-License-Identifier: CC-BY-NC-SA-4.0
//! Numerically stable presentation of modeled loss probabilities.
//!
//! Subtracting 1e-20 from an f64 one produces one. Percentage presentation instead
//! subtracts the three-significant-digit decimal loss from an integer power of ten.
//! This is formatting, not a claim that a finite simulation resolves twenty nines.
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
/// Presentation fields accompany, rather than replace, numeric estimator output.
pub struct Durability {
    pub loss_probability: String,
    pub durability_percent: String,
    pub nines: Option<f64>,
    pub interpretation: &'static str,
}

/// Format positive finite estimates without subtracting tiny values from f64 one.
pub fn describe(p: f64) -> Durability {
    if !p.is_finite() || !(0.0..=1.0).contains(&p) {
        return Durability {
            loss_probability: "invalid".into(),
            durability_percent: "unavailable".into(),
            nines: None,
            interpretation: "probability must be finite and within 0..=1",
        };
    }
    if p == 0.0 {
        return Durability { loss_probability: "0.00e+00".into(), durability_percent: "unresolved (zero estimated loss)".into(), nines: None, interpretation: "zero estimated/observed loss is not evidence of infinite durability; inspect confidence bounds and sample size" };
    }
    let scientific = format!("{p:.2e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap();
    let exponent: i32 = exponent.parse().unwrap();
    let loss_probability = format!("{mantissa}e{exponent:+03}");
    let percent = if exponent >= -35 {
        let digits = (-exponent).max(0) as u32;
        let scale = 10u128.pow(digits);
        let coefficient: u128 = mantissa.replace('.', "").parse().unwrap();
        let loss = coefficient * 10u128.pow((exponent + digits as i32) as u32);
        let remaining = 100 * scale - loss;
        if digits == 0 {
            format!("{remaining}%")
        } else {
            let decimal = format!("{:0width$}", remaining % scale, width = digits as usize);
            let decimal = decimal.trim_end_matches('0');
            if decimal.is_empty() {
                format!("{}%", remaining / scale)
            } else {
                format!("{}.{decimal}%", remaining / scale)
            }
        }
    } else {
        format!("100% minus {:.2e}%", p * 100.0)
    };
    Durability { loss_probability, durability_percent: percent, nines: Some(-p.log10()), interpretation: "modeled estimate; percentage rounded from three significant loss digits; nines=-log10(p), subject to model assumptions and estimator uncertainty" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn twenty_nines_survive_decimal_formatting() {
        let d = describe(1e-20);
        assert_eq!(d.loss_probability, "1.00e-20");
        assert_eq!(d.nines, Some(20.0));
        assert_eq!(d.durability_percent, "99.999999999999999999%");
    }
    #[test]
    fn fractional_nines_and_boundaries() {
        let d = describe(2.5e-5);
        assert_eq!(d.durability_percent, "99.9975%");
        assert!((d.nines.unwrap() - 4.602059991).abs() < 1e-8);
        assert_eq!(describe(1.0).durability_percent, "0%");
        assert_eq!(describe(0.0).nines, None);
        assert_eq!(describe(f64::NAN).nines, None);
        assert_eq!(describe(-0.1).nines, None);
        assert!(describe(1e-100).durability_percent.contains("minus"));
    }
}
