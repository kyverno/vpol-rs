use cel::common::types::{DYN_TYPE, Kind, STRING_TYPE, Type};
use cel::common::value::CowVal;
use cel::{DeclarationError, Env, ExecutionError, Library, Value};
use kube_cel::cel;

use super::common::{
    json_to_value, opaque_val, receiver, string_arg, to_cow, to_go_json, value_arg, value_to_json,
};

pub static JSON_TYPE: Type = Type::simple_type(Kind::Opaque, "json.Json");

/// The value bound to `json`: the receiver of `json.unmarshal` and `json.marshal`.
#[derive(Clone, Debug)]
pub struct Json;

opaque_val!(Json, JSON_TYPE);

/// Kyverno's `json` CEL library: `json.unmarshal(string) -> dyn` and
/// `json.marshal(dyn) -> string`, methods on the `json` variable.
pub struct JsonLib;

impl JsonLib {
    pub fn new() -> Self {
        JsonLib
    }
}

impl Library for JsonLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.json")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        env.add_type(JSON_TYPE.to_owned())?;
        env.add_member_overload(
            "unmarshal",
            "unmarshal_string_dyn",
            JSON_TYPE.to_owned(),
            vec![STRING_TYPE],
            unmarshal,
        )?;
        env.add_member_overload(
            "marshal",
            "marshal_dyn_string",
            JSON_TYPE.to_owned(),
            vec![DYN_TYPE],
            marshal,
        )?;
        Ok(())
    }
}

/// Parses a JSON document.
// cel's `Function` type takes the arguments by value.
#[allow(clippy::needless_pass_by_value)]
fn unmarshal<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    receiver::<Json>(&args)?;
    let parsed: serde_json::Value = serde_json::from_str(string_arg(&args, 1)?)
        .map_err(|e| ExecutionError::function_error("json.unmarshal", e))?;
    to_cow(json_to_value(&parsed))
}

/// Encodes a value as JSON.
// cel's `Function` type takes the arguments by value.
#[allow(clippy::needless_pass_by_value)]
fn marshal<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    receiver::<Json>(&args)?;
    let json = value_to_json(&value_arg(&args, 1)?)?;
    to_cow(Value::String(to_go_json(&json).into()))
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    #[test]
    fn round_trips() {
        for expr in [
            r#"json.unmarshal('{"a": [1, "x", null]}').a[0] == 1"#,
            r#"json.marshal({"b": 2.0, "a": [true, null]}) == '{"a":[true,null],"b":2}'"#,
            r#"json.unmarshal(json.marshal({"k": "v"})) == {"k": "v"}"#,
            // As Go's json.Marshal: HTML characters escaped, floats in Go's notation.
            r#"json.marshal("a&b<c>") == r'"a\u0026b\u003cc\u003e"'"#,
            r#"json.marshal(timestamp('2024-01-01T00:00:00.500Z')) == '"2024-01-01T00:00:00.5Z"'"#,
        ] {
            assert_eq!(eval(expr), Ok(Value::Bool(true)), "{expr}");
        }
        assert!(eval("json.unmarshal('{')").is_err());
    }
}
