use cel::common::types::{Kind, STRING_TYPE, Type};
use cel::common::value::CowVal;
use cel::{DeclarationError, Env, ExecutionError, Library};
use kube_cel::cel;
use serde::Deserialize as _;

use super::common::{json_to_value, opaque_val, receiver, string_arg, to_cow};

pub static YAML_TYPE: Type = Type::simple_type(Kind::Opaque, "yaml.Yaml");

/// The value bound to `yaml`: the receiver of `yaml.parse`.
#[derive(Clone, Debug)]
pub struct Yaml;

opaque_val!(Yaml, YAML_TYPE);

/// Kyverno's `yaml` CEL library: `yaml.parse(string) -> dyn`, a method on the
/// `yaml` variable.
pub struct YamlLib;

impl YamlLib {
    pub fn new() -> Self {
        YamlLib
    }
}

impl Library for YamlLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.yaml")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        env.add_type(YAML_TYPE.to_owned())?;
        env.add_member_overload(
            "parse",
            "parse_string_dyn",
            YAML_TYPE.to_owned(),
            vec![STRING_TYPE],
            parse,
        )?;
        Ok(())
    }
}

/// Parses the first YAML document into the value its JSON form would give, as
/// `sigs.k8s.io/yaml` does: merge keys applied, non-string keys as strings.
// cel's `Function` type takes the arguments by value.
#[allow(clippy::needless_pass_by_value)]
fn parse<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    receiver::<Yaml>(&args)?;
    let fail = |e| ExecutionError::function_error("yaml.parse", e);
    // Only the first document counts, as in Go; no document at all is null.
    let mut parsed = match serde_yaml_ng::Deserializer::from_str(string_arg(&args, 1)?).next() {
        Some(document) => serde_yaml_ng::Value::deserialize(document).map_err(fail)?,
        None => serde_yaml_ng::Value::Null,
    };
    parsed.apply_merge().map_err(fail)?;
    to_cow(json_to_value(&yaml_to_json(parsed)?))
}

fn yaml_to_json(yaml: serde_yaml_ng::Value) -> Result<serde_json::Value, ExecutionError> {
    use serde_yaml_ng::Value as Y;
    Ok(match yaml {
        Y::Null => serde_json::Value::Null,
        Y::Bool(b) => b.into(),
        // JSON has no NaN or infinities: Go fails on them too.
        Y::Number(n) if n.as_f64().is_some_and(|f| !f.is_finite()) => {
            return Err(ExecutionError::function_error(
                "yaml.parse",
                format!("unsupported value: {n}"),
            ));
        }
        Y::Number(n) => {
            serde_json::to_value(&n).map_err(|e| ExecutionError::function_error("yaml.parse", e))?
        }
        Y::String(s) => s.into(),
        Y::Sequence(items) => items
            .into_iter()
            .map(yaml_to_json)
            .collect::<Result<Vec<_>, _>>()?
            .into(),
        Y::Mapping(fields) => fields
            .into_iter()
            .map(|(k, v)| Ok((yaml_key(k)?, yaml_to_json(v)?)))
            .collect::<Result<serde_json::Map<_, _>, ExecutionError>>()?
            .into(),
        Y::Tagged(tagged) => yaml_to_json(tagged.value)?,
    })
}

/// A mapping key as a string, as `sigs.k8s.io/yaml` converts it.
fn yaml_key(key: serde_yaml_ng::Value) -> Result<String, ExecutionError> {
    use serde_yaml_ng::Value as Y;
    match key {
        Y::String(s) => Ok(s),
        Y::Bool(b) => Ok(b.to_string()),
        Y::Number(n) => Ok(n.to_string()),
        Y::Tagged(tagged) => yaml_key(tagged.value),
        Y::Null | Y::Sequence(_) | Y::Mapping(_) => Err(ExecutionError::function_error(
            "yaml.parse",
            "unsupported mapping key: null, a sequence or a mapping",
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    #[test]
    fn parses_documents() {
        for expr in [
            "yaml.parse('a: 1\\nb: [x, true]') == {'a': 1, 'b': ['x', true]}",
            "yaml.parse('1: one')['1'] == 'one'",
            "yaml.parse('a: 1\\n---\\nb: 2') == {'a': 1}",
            "yaml.parse('base: &b {x: 1}\\nd:\\n  <<: *b\\n  y: 2').d == {'x': 1, 'y': 2}",
        ] {
            assert_eq!(eval(expr), Ok(Value::Bool(true)), "{expr}");
        }
        assert!(eval("yaml.parse('a: [')").is_err());
        assert!(eval("yaml.parse('a: .inf')").is_err());
    }
}
