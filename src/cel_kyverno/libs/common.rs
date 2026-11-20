//! Helpers shared by the libraries: JSON <-> CEL value conversion, argument
//! access, and the boilerplate for opaque receiver types (`json`, `yaml`, `http`).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cel::common::types::CelString;
use cel::common::value::{CowVal, Val};
use cel::objects::Key;
use cel::{ExecutionError, Value};
use kube_cel::cel;

/// Implements [`Val`] for a unit-like opaque type, so it can be bound as a
/// variable and used as the receiver of member overloads.
macro_rules! opaque_val {
    ($ty:ty, $cel_type:expr) => {
        impl ::kube_cel::cel::common::value::Val for $ty {
            fn get_type(&self) -> &::kube_cel::cel::common::types::Type {
                &$cel_type
            }

            fn cel_type() -> &'static ::kube_cel::cel::common::types::Type {
                &$cel_type
            }

            fn clone_as_boxed<'v>(&self) -> Box<dyn ::kube_cel::cel::common::value::Val + 'v> {
                Box::new(self.clone())
            }

            fn as_any(&self) -> Option<&dyn ::std::any::Any> {
                Some(self)
            }
        }

        impl ::kube_cel::cel::common::value::StaticVal for $ty {}
    };
}
pub(crate) use opaque_val;

/// Converts JSON to a CEL value. Integers become `int` when they fit in an
/// `i64`, as Kubernetes' CEL does, rather than `uint` or `double`.
pub fn json_to_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(u) = n.as_u64() {
                Value::UInt(u)
            } else {
                Value::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        serde_json::Value::String(s) => Value::String(Arc::new(s.clone())),
        serde_json::Value::Array(items) => {
            Value::List(Arc::new(items.iter().map(json_to_value).collect()))
        }
        serde_json::Value::Object(fields) => fields
            .iter()
            .map(|(k, v)| (k.clone(), json_to_value(v)))
            .collect::<HashMap<_, _>>()
            .into(),
    }
}

/// Converts a CEL value to JSON, as Go's `encoding/json` would encode its
/// native form: bytes as base64, timestamps as RFC 3339, durations as
/// nanoseconds, and map keys sorted. Map keys must be strings.
pub fn value_to_json(value: &Value) -> Result<serde_json::Value, ExecutionError> {
    Ok(match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => (*b).into(),
        Value::Int(i) => (*i).into(),
        Value::UInt(u) => (*u).into(),
        Value::Float(f) => float_to_json(*f)?,
        Value::String(s) => s.as_str().into(),
        Value::Bytes(b) => BASE64.encode(b.as_slice()).into(),
        Value::List(items) => items
            .iter()
            .map(value_to_json)
            .collect::<Result<Vec<_>, _>>()?
            .into(),
        Value::Map(map) => {
            let mut fields = BTreeMap::new();
            for (key, value) in map.map.iter() {
                let Key::String(key) = key else {
                    return Err(ExecutionError::function_error(
                        "json",
                        format!("unsupported map key {key:?}, want string"),
                    ));
                };
                fields.insert(key.as_str().to_owned(), value_to_json(value)?);
            }
            serde_json::Value::Object(fields.into_iter().collect())
        }
        Value::Timestamp(ts) => rfc3339_nano(ts).into(),
        Value::Duration(d) => d
            .num_nanoseconds()
            .ok_or_else(|| ExecutionError::function_error("json", "duration out of range"))?
            .into(),
        other => {
            return Err(ExecutionError::function_error(
                "json",
                format!("unsupported value of type {}", other.type_of()),
            ));
        }
    })
}

/// A double as JSON: NaN and infinities are errors, as in Go. How it's
/// written is up to [`to_go_json`].
fn float_to_json(f: f64) -> Result<serde_json::Value, ExecutionError> {
    serde_json::Number::from_f64(f)
        .map(serde_json::Value::Number)
        .ok_or_else(|| ExecutionError::function_error("json", format!("unsupported value: {f}")))
}

/// A timestamp as Go's `time.RFC3339Nano` formats it: the fraction of a
/// second without trailing zeros, and `Z` for UTC.
fn rfc3339_nano(ts: &chrono::DateTime<chrono::FixedOffset>) -> String {
    let full = ts.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let Some(dot) = full.find('.') else {
        return full;
    };
    let digits_end = full[dot + 1..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(full.len(), |i| dot + 1 + i);
    let fraction = full[dot + 1..digits_end].trim_end_matches('0');
    let sep = if fraction.is_empty() { "" } else { "." };
    format!("{}{sep}{fraction}{}", &full[..dot], &full[digits_end..])
}

/// Serializes JSON as Go's `json.Marshal` writes it: compact, `<`, `>`, `&`,
/// U+2028 and U+2029 escaped in strings, and floats in Go's notation.
pub fn to_go_json(value: &serde_json::Value) -> String {
    use serde::Serialize as _;
    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, GoFormatter);
    value
        .serialize(&mut serializer)
        .expect("serializing a serde_json::Value into a Vec can't fail");
    String::from_utf8(out).expect("serde_json writes UTF-8")
}

struct GoFormatter;

impl serde_json::ser::Formatter for GoFormatter {
    fn write_f64<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        value: f64,
    ) -> std::io::Result<()> {
        w.write_all(go_float(value).as_bytes())
    }

    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let escaped = match c {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            w.write_all(&fragment.as_bytes()[start..i])?;
            w.write_all(escaped.as_bytes())?;
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }
}

/// A float as Go's encoding/json writes it: plain decimal for
/// `1e-6 <= |f| < 1e21`, otherwise exponent notation with a signed exponent.
fn go_float(f: f64) -> String {
    let abs = f.abs();
    if abs == 0.0 || (1e-6..1e21).contains(&abs) {
        return format!("{f}");
    }
    let exp = format!("{f:e}");
    match exp.split_once('e') {
        Some((mantissa, e)) if !e.starts_with('-') => format!("{mantissa}e+{e}"),
        _ => exp,
    }
}

/// Wraps a [`Value`] as an overload's result.
pub fn to_cow<'b, 'v>(value: Value) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let val: Box<dyn Val> = value.try_into()?;
    Ok(CowVal::Owned(val))
}

/// The argument at `index` as a [`Value`].
pub fn value_arg(args: &[CowVal<'_, '_>], index: usize) -> Result<Value, ExecutionError> {
    Value::try_from(args[index].as_ref())
}

/// The the argument at `index` as a string.
pub fn string_arg<'a>(args: &'a [CowVal<'_, '_>], index: usize) -> Result<&'a str, ExecutionError> {
    args[index]
        .as_ref()
        .downcast_ref::<CelString>()
        .map(CelString::inner)
        .ok_or_else(|| ExecutionError::UnexpectedType {
            got: args[index].as_ref().get_type().name().into(),
            want: "string".into(),
        })
}

/// Extract the first argument from a list of CEL argument, which is the method's receiver.
/// The result is a value of type T (that receiver's type) that doesn't outlive the argument's
/// whose lifetime is denoted by 'a
pub fn receiver<'a, T: cel::common::value::StaticVal>(
    args: &'a [CowVal<'_, '_>],
) -> Result<&'a T, ExecutionError> {
    args[0]
        .as_ref()
        .downcast_ref::<T>()
        .ok_or_else(|| ExecutionError::UnexpectedType {
            got: args[0].as_ref().get_type().name().into(),
            want: T::cel_type().name().into(),
        })
}
