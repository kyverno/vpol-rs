use kube_cel::cel;
use std::io::{Read as _, Write as _};

use cel::common::types::{CelBytes, CelString};
use cel::{DeclarationError, Env, ExecutionError, Library};
use flate2::read::MultiGzDecoder;
use flate2::{Compression, GzBuilder};

/// Kyverno's `gzip` CEL library: `gzip.compress(string) -> bytes` and
/// `gzip.decompress(bytes) -> string`.
pub struct GzipLib;

impl GzipLib {
    pub fn new() -> Self {
        GzipLib
    }
}

impl Library for GzipLib {
    fn name(&self) -> Option<&str> {
        Some("kyverno.gzip")
    }

    fn register(&self, env: &mut Env) -> Result<(), DeclarationError> {
        cel::add_overload!(env, fn decompress: (CelBytes) -> Result<CelString>,
            name = "gzip.decompress", id = "decompress_bytes_string")?;
        cel::add_overload!(env, fn compress: (CelString) -> Result<CelBytes>,
            name = "gzip.compress", id = "compress_any_bytes")?;
        Ok(())
    }
}

/// Decompresses gzip data, following concatenated members as Go's reader does,
/// and returns it as a string. Go keeps invalid UTF-8 as is; CEL strings here
/// must be valid, so invalid sequences become U+FFFD.
fn decompress(data: &CelBytes<'_>) -> Result<CelString<'static>, ExecutionError> {
    let mut out = Vec::new();
    MultiGzDecoder::new(data.inner())
        .read_to_end(&mut out)
        .map_err(|e| ExecutionError::function_error("gzip.decompress", e))?;
    Ok(String::from_utf8_lossy(&out).into_owned().into())
}

/// Compresses a string with the default level. The header's mtime is left at
/// zero so the output is deterministic.
fn compress(value: &CelString<'_>) -> Result<CelBytes<'static>, ExecutionError> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder
        .write_all(value.inner().as_bytes())
        .and_then(|()| encoder.finish())
        .map(CelBytes::from)
        .map_err(|e| ExecutionError::function_error("gzip.compress", e))
}

#[cfg(test)]
mod tests {
    use crate::cel_kyverno::compiler::compile::eval;
    use kube_cel::cel::Value;

    #[test]
    fn round_trips() {
        assert_eq!(
            eval("gzip.decompress(gzip.compress('kyverno')) == 'kyverno'"),
            Ok(Value::Bool(true))
        );
        assert!(eval("gzip.decompress(b'not gzip')").is_err());
    }
}
