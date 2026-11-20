use kube_cel::cel;
use std::collections::BTreeMap;
use std::sync::Arc;

use cel::{ExecutionError, Program, Value};

use crate::cel_kyverno::compiler::compile::new_vpol_context;
use crate::cel_kyverno::compiler::variables::Variables;
use crate::cel_kyverno::libs::common::json_to_value;

/// Why evaluating a compiled policy failed.
#[derive(Debug, thiserror::Error)]
pub enum EvaluationError {
    /// The evaluation context couldn't be built: kube-cel's context functions
    /// failed to register.
    #[error("building evaluation context: {0}")]
    Context(#[from] kube_cel::RegisterError),

    /// A match condition failed while executing.
    #[error("match condition {name:?}: {source}")]
    MatchCondition {
        name: String,
        #[source]
        source: ExecutionError,
    },

    /// A match condition returned something other than a bool.
    #[error("match condition {name:?} returned {got}, want bool")]
    MatchConditionNotBool { name: String, got: String },

    /// A validation failed while executing.
    #[error("validation {index}: {source}")]
    Validation {
        index: usize,
        #[source]
        source: ExecutionError,
    },

    /// A validation returned something other than a bool.
    #[error("validation {index} returned {got}, want bool")]
    ValidationNotBool { index: usize, got: String },
}

/// A match condition, compiled, with its name for reporting.
pub struct MatchCondition {
    pub name: String,
    pub program: Program,
}

pub struct CompiledPolicy {
    name: String,
    /// In rust-cel, the program doesn't hold a reference to the environment. Store the
    /// env so we can later create a Context from it and pass to the program.
    env: Arc<cel::Env>,
    variables: Arc<BTreeMap<String, Program>>,
    match_conditions: Vec<MatchCondition>,
    validations: Vec<Program>,
}

impl CompiledPolicy {
    pub fn new(
        name: String,
        env: Arc<cel::Env>,
        variables: BTreeMap<String, Program>,
        match_conditions: Vec<MatchCondition>,
        validations: Vec<Program>,
    ) -> Self {
        CompiledPolicy {
            name,
            env,
            variables: Arc::new(variables),
            match_conditions,
            validations,
        }
    }

    /// The policy's `metadata.name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Evaluates the policy against `object`, bound as `object` in every
    /// expression, with the policy's variables under `variables`.
    ///
    /// Returns `true` when the policy doesn't apply (a match condition is false)
    /// or every validation passes, and `false` as soon as one validation fails.
    pub fn evaluate(&self, object: &serde_json::Value) -> Result<bool, EvaluationError> {
        let mut base = new_vpol_context(Arc::clone(&self.env))?;
        base.add_variable_from_value("object", json_to_value(object));
        let base = Arc::new(base);

        // Variables are evaluated lazily, on first access, in a scope that sees
        // `object` and the other variables.
        let mut ctx = base.new_inner_scope();
        ctx.add_variable_as_val(
            "variables",
            Box::new(Variables::new(
                Arc::clone(&self.variables),
                Arc::clone(&base),
            )),
        );

        for condition in &self.match_conditions {
            let matched = match condition.program.execute(&ctx) {
                Ok(Value::Bool(b)) => b,
                Ok(other) => {
                    return Err(EvaluationError::MatchConditionNotBool {
                        name: condition.name.clone(),
                        got: other.type_of().to_string(),
                    });
                }
                Err(source) => {
                    return Err(EvaluationError::MatchCondition {
                        name: condition.name.clone(),
                        source,
                    });
                }
            };
            if !matched {
                return Ok(true);
            }
        }

        for (index, validation) in self.validations.iter().enumerate() {
            match validation.execute(&ctx) {
                Ok(Value::Bool(true)) => {}
                Ok(Value::Bool(false)) => return Ok(false),
                Ok(other) => {
                    return Err(EvaluationError::ValidationNotBool {
                        index,
                        got: other.type_of().to_string(),
                    });
                }
                Err(source) => return Err(EvaluationError::Validation { index, source }),
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cel_kyverno::compiler::compile::Compiler;
    use serde_json::json;

    fn compile(spec: &str) -> CompiledPolicy {
        let policy = serde_yaml_ng::from_str(&format!("metadata: {{name: test}}\nspec:\n{spec}"))
            .expect("valid policy YAML");
        Compiler::compile(&policy).expect("the policy compiles")
    }

    const REPLICAS: &str = "
  matchConditions:
    - name: is-deployment
      expression: object.kind == 'Deployment'
  variables:
    - name: replicas
      expression: object.spec.replicas
    - name: limit
      expression: variables.replicas <= 5
  validations:
    - expression: variables.limit
";

    #[test]
    fn evaluates_validations_through_variables() {
        let policy = compile(REPLICAS);
        let deployment = |n: i64| json!({"kind": "Deployment", "spec": {"replicas": n}});
        assert!(policy.evaluate(&deployment(3)).unwrap());
        assert!(!policy.evaluate(&deployment(7)).unwrap());
    }

    #[test]
    fn passes_when_a_match_condition_is_false() {
        let policy = compile(REPLICAS);
        let pod = json!({"kind": "Pod", "spec": {"replicas": 7}});
        assert!(policy.evaluate(&pod).unwrap());
    }

    #[test]
    fn json_integers_are_ints() {
        let policy = compile("  validations:\n    - expression: type(object.n) == int");
        assert!(policy.evaluate(&json!({"n": 3})).unwrap());
    }

    #[test]
    fn reports_errors_by_stage() {
        let not_bool = compile("  validations:\n    - expression: \"'yes'\"");
        assert!(matches!(
            not_bool.evaluate(&json!({})),
            Err(EvaluationError::ValidationNotBool { index: 0, .. })
        ));

        let failing = compile(
            "  matchConditions:\n    - name: m\n      expression: object.missing\n  validations: []",
        );
        assert!(matches!(
            failing.evaluate(&json!({})),
            Err(EvaluationError::MatchCondition { .. })
        ));

        let cyclic = compile(
            "  variables:\n    - name: a\n      expression: variables.b\n    - name: b\n      expression: variables.a\n  validations:\n    - expression: variables.a",
        );
        assert!(matches!(
            cyclic.evaluate(&json!({})),
            Err(EvaluationError::Validation { .. })
        ));
    }
}
