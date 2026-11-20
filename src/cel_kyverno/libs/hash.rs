use cel::common::types::CelString;
use cel::{DeclarationError, Env, Library};
use kube_cel::cel;
use md5::Md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// Kyverno's `hash` CEL library: hex-encoded `sha1`, `sha256` and `md5` digests
/// of a string, available both unprefixed and under the `hash.` namespace.
pub struct HashLib;

impl HashLib {
    pub fn new() -> Self {
        HashLib
    }
}

impl Library for HashLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.hash")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        cel::add_overload!(env, fn sha1_hex: (CelString) -> CelString,
            name = "sha1", id = "sha1_string_non_prefixed")?;
        cel::add_overload!(env, fn sha256_hex: (CelString) -> CelString,
            name = "sha256", id = "sha256_string_non_prefixed")?;
        cel::add_overload!(env, fn md5_hex: (CelString) -> CelString,
            name = "md5", id = "md5_string_non_prefixed")?;

        cel::add_overload!(env, fn sha1_hex: (CelString) -> CelString,
            name = "hash.sha1", id = "sha1_string_prefixed")?;
        cel::add_overload!(env, fn sha256_hex: (CelString) -> CelString,
            name = "hash.sha256", id = "sha256_string_prefixed")?;
        cel::add_overload!(env, fn md5_hex: (CelString) -> CelString,
            name = "hash.md5", id = "md5_string_prefixed")?;
        Ok(())
    }
}

fn sha1_hex(value: &CelString<'_>) -> CelString<'static> {
    digest_hex::<Sha1>(value)
}

fn sha256_hex(value: &CelString<'_>) -> CelString<'static> {
    digest_hex::<Sha256>(value)
}

fn md5_hex(value: &CelString<'_>) -> CelString<'static> {
    digest_hex::<Md5>(value)
}

/// Hashes the UTF-8 bytes of `value` with `D` and hex-encodes the digest.
fn digest_hex<D: Digest>(value: &CelString<'_>) -> CelString<'static> {
    hex::encode(D::digest(value.inner().as_bytes())).into()
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    #[test]
    fn hashes_strings_to_hex() {
        for expr in [
            "sha256('hello') == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'",
            "hash.sha1('hello') == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'",
            "md5('hello') == hash.md5('hello') && md5('hello') == '5d41402abc4b2a76b9719d911017c592'",
        ] {
            assert_eq!(eval(expr), Ok(Value::Bool(true)), "{expr}");
        }
    }
}
