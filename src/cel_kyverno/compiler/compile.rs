use crate::cel_kyverno::compiler::policy::{CompiledPolicy, MatchCondition};
use crate::cel_kyverno::compiler::variables::VARIABLES_TYPE;
use crate::cel_kyverno::libs::{
    gzip::GzipLib,
    hash::HashLib,
    http::{HTTP, HttpLib},
    json::{Json, JsonLib},
    math::MathLib,
    random::RandomLib,
    time::TimeLib,
    x509::X509Lib,
    yaml::{Yaml, YamlLib},
};
use cel::{DeclarationError, ParseErrors};
use kube_cel::cel;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Why a policy failed to compile.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// The CEL environment couldn't be built: a type or library failed to register.
    #[error("building CEL environment: {0}")]
    Env(#[from] DeclarationError),

    /// An expression in the policy isn't valid CEL.
    #[error("{path}: {source}")]
    Expression {
        /// Where the expression sits in the policy, e.g. `spec.validations[2].expression`.
        path: String,
        #[source]
        source: ParseErrors,
    },
}

pub struct Compiler;

impl Compiler {
    pub fn compile(
        policy: &crate::api::vpol::ValidatingPolicy,
    ) -> Result<CompiledPolicy, CompileError> {
        let env = new_vpol_env()?;

        // Compile match expressions
        let compiled_matchconds = policy
            .spec
            .match_conditions
            .iter()
            .flatten()
            .enumerate()
            .map(|(i, m)| {
                compile_expression(&env, &m.expression, || {
                    format!("spec.matchConditions[{i}].expression")
                })
                .map(|program| MatchCondition {
                    name: m.name.clone(),
                    program,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Compile variables, keyed by name
        let vars = policy
            .spec
            .variables
            .iter()
            .flatten()
            .enumerate()
            .map(|(i, v)| {
                compile_expression(&env, &v.expression, || {
                    format!("spec.variables[{i}].expression")
                })
                .map(|program| (v.name.clone(), program))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let compiled_validations = policy
            .spec
            .validations
            .iter()
            .flatten()
            .enumerate()
            .map(|(i, v)| {
                compile_expression(&env, &v.expression, || {
                    format!("spec.validations[{i}].expression")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(CompiledPolicy::new(
            policy.metadata.name.clone().unwrap_or_default(),
            Arc::new(env),
            vars,
            compiled_matchconds,
            compiled_validations,
        ))
    }
}

/// Compiles `expression`, recording the policy field it came from on failure.
fn compile_expression(
    env: &cel::Env,
    expression: &str,
    path: impl FnOnce() -> String,
) -> Result<cel::Program, CompileError> {
    env.compile(expression)
        .map_err(|source| CompileError::Expression {
            path: path(),
            source,
        })
}

pub(crate) fn new_vpol_env() -> Result<cel::Env, DeclarationError> {
    // kube-cel's environment: the cel stdlib plus the parts of the Kubernetes
    // libraries that live on the env. The rest live on the context, which
    // `kube_cel::new_context` adds when a policy is evaluated.
    let mut env = kube_cel::new_env();
    // Register the variables type
    env.add_type(VARIABLES_TYPE.to_owned())?;
    env.add_library(RandomLib::new())?;
    env.add_library(GzipLib::new())?;
    env.add_library(HashLib::new())?;
    env.add_library(MathLib::new())?;
    env.add_library(TimeLib::new())?;
    env.add_library(JsonLib::new())?;
    env.add_library(YamlLib::new())?;
    env.add_library(X509Lib::new())?;
    env.add_library(HttpLib::new())?;
    Ok(env)
}

/// A root context on `env` (from [`new_vpol_env`]): kube-cel's context
/// functions, and the `json`, `yaml` and `http` receivers bound.
pub(crate) fn new_vpol_context(
    env: Arc<cel::Env>,
) -> Result<cel::Context<'static, 'static>, kube_cel::RegisterError> {
    let mut ctx = kube_cel::new_context(env)?;
    ctx.add_variable_as_val("json", Box::new(Json));
    ctx.add_variable_as_val("yaml", Box::new(Yaml));
    ctx.add_variable_as_val("http", Box::new(HTTP.clone()));
    Ok(ctx)
}

/// Compiles and runs `expression` in the policy environment, with no variables.
#[cfg(test)]
pub(crate) fn eval(expression: &str) -> Result<cel::Value, cel::ExecutionError> {
    let env = Arc::new(new_vpol_env().expect("the environment builds"));
    let ctx = new_vpol_context(Arc::clone(&env)).expect("the context builds");
    env.compile(expression)
        .expect("the expression parses")
        .execute(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_the_path_of_an_invalid_expression() {
        let policy = serde_yaml_ng::from_str(
            "metadata: {name: p}\nspec:\n  validations:\n    - expression: 'true'\n    - expression: '1 +'\n",
        )
        .unwrap();
        let Err(CompileError::Expression { path, .. }) = Compiler::compile(&policy) else {
            panic!("expected an expression error");
        };
        assert_eq!(path, "spec.validations[1].expression");
    }
}
