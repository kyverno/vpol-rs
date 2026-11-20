use cel::common::types::{CelDouble, CelInt};
use cel::{DeclarationError, Env, Library};
use kube_cel::cel;

/// Kyverno's `math` CEL library: `math.round(double, int) -> double`.
pub struct MathLib;

impl MathLib {
    pub fn new() -> Self {
        MathLib
    }
}

impl Library for MathLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.math")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        cel::add_overload!(env, fn round: (CelDouble, CelInt) -> CelDouble,
            name = "math.round", id = "math_round_float_int")?;
        Ok(())
    }
}

/// Rounds `value` to `precision` decimal places, half away from zero. A
/// negative precision rounds to tens, hundreds, and so on.
// `add_overload!` passes every argument by reference.
#[allow(clippy::cast_precision_loss, clippy::trivially_copy_pass_by_ref)]
fn round(value: &CelDouble, precision: &CelInt) -> CelDouble {
    let shift = 10f64.powf(*precision.inner() as f64);
    CelDouble::from((value.inner() * shift).round() / shift)
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    // The cases from Kyverno's tests.
    #[test]
    fn rounds_to_precision() {
        assert_eq!(eval("math.round(10.125, 2)"), Ok(Value::Float(10.13)));
        assert_eq!(eval("math.round(10.125, 0)"), Ok(Value::Float(10.0)));
        assert_eq!(
            eval("math.round(12345.6789, -2)"),
            Ok(Value::Float(12300.0))
        );
    }
}
