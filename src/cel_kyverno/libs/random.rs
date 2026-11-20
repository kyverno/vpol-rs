use cel::common::types::CelString;
use cel::{DeclarationError, Env, ExecutionError, Library};
use kube_cel::cel;
use rand::RngExt as _;

/// Pattern used by `random.random()` when no pattern is given.
const DEFAULT_PATTERN: &str = "[0-9a-z]{8}";

/// Upper bound on repetitions for unbounded quantifiers (`*`, `+`, `{n,}`).
const MAX_REPEAT: u32 = 64;

pub struct RandomLib;

impl RandomLib {
    pub fn new() -> Self {
        RandomLib
    }
}

impl Library for RandomLib {
    fn name(&self) -> Option<&str> {
        Some("random")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        cel::add_overload!(env, fn random: () -> Result<CelString>,
            name = "random.random", id = "random_default")?;
        cel::add_overload!(env, fn random_with_pattern: (CelString) -> Result<CelString>,
            name = "random.random", id = "random_regex")?;
        Ok(())
    }
}

fn random() -> Result<CelString<'static>, ExecutionError> {
    generate(DEFAULT_PATTERN)
}

fn random_with_pattern(pattern: &CelString<'_>) -> Result<CelString<'static>, ExecutionError> {
    generate(pattern.inner())
}

/// Generates a random string matching the regex `pattern`.
fn generate(pattern: &str) -> Result<CelString<'static>, ExecutionError> {
    let regex = rand_regex::Regex::compile(pattern, MAX_REPEAT)
        .map_err(|e| ExecutionError::function_error("random.random", e))?;
    let value: String = rand::rng().sample(&regex);
    Ok(value.into())
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    #[test]
    fn generates_matching_strings() {
        for expr in [
            "random.random().matches('^[0-9a-z]{8}$')",
            "random.random('[A-Z]{3}-[0-9]{2}').matches('^[A-Z]{3}-[0-9]{2}$')",
        ] {
            assert_eq!(eval(expr), Ok(Value::Bool(true)), "{expr}");
        }
        assert!(eval("random.random('(')").is_err());
    }
}
