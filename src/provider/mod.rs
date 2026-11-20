use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::vpol::ValidatingPolicy;
use crate::cel_kyverno::compiler::compile::{CompileError, Compiler};
use crate::cel_kyverno::compiler::policy::CompiledPolicy;

/// Why policies couldn't be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("compiling policy {name:?}: {source}")]
    Compile {
        name: String,
        #[source]
        source: CompileError,
    },
}

/// The result of evaluating an object against every loaded policy.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Whether every policy passed (or didn't apply).
    pub allowed: bool,
    pub results: Vec<PolicyResult>,
}

#[derive(Debug, Serialize)]
pub struct PolicyResult {
    pub policy: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum Outcome {
    /// The policy passed, or a match condition excluded the object.
    Pass,
    /// A validation returned false.
    Fail,
    /// Evaluation failed.
    Error { error: String },
}

/// Holds the compiled policies and evaluates objects against them.
pub struct Provider {
    policies: Vec<CompiledPolicy>,
}

impl Provider {
    pub fn new(policies: Vec<CompiledPolicy>) -> Self {
        Provider { policies }
    }

    /// Loads and compiles the policies in `paths`. A path can be a file or a
    /// directory, whose `.yaml`, `.yml` and `.json` files are read (not
    /// recursively). A file can hold several YAML documents.
    pub fn load(paths: &[PathBuf]) -> Result<Self, LoadError> {
        let mut policies = Vec::new();
        for path in paths {
            for file in policy_files(path)? {
                let source = fs::read_to_string(&file).map_err(|source| LoadError::Io {
                    path: file.clone(),
                    source,
                })?;
                let parsed = parse_policies(&source).map_err(|source| LoadError::Parse {
                    path: file.clone(),
                    source,
                })?;
                for policy in &parsed {
                    policies.push(Compiler::compile(policy).map_err(|source| {
                        LoadError::Compile {
                            name: policy.metadata.name.clone().unwrap_or_default(),
                            source,
                        }
                    })?);
                }
            }
        }
        Ok(Provider::new(policies))
    }

    /// Evaluates `object` against every policy.
    pub fn evaluate(&self, object: &serde_json::Value) -> Report {
        let results: Vec<_> = self
            .policies
            .iter()
            .map(|policy| PolicyResult {
                policy: policy.name().to_owned(),
                outcome: match policy.evaluate(object) {
                    Ok(true) => Outcome::Pass,
                    Ok(false) => Outcome::Fail,
                    Err(e) => Outcome::Error {
                        error: e.to_string(),
                    },
                },
            })
            .collect();
        Report {
            allowed: results.iter().all(|r| r.outcome == Outcome::Pass),
            results,
        }
    }
}

/// The policy files `path` names: itself, or the YAML and JSON files in it,
/// sorted so policies load in a stable order.
fn policy_files(path: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let io_err = |source| LoadError::Io {
        path: path.to_owned(),
        source,
    };
    if !fs::metadata(path).map_err(io_err)?.is_dir() {
        return Ok(vec![path.to_owned()]);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(io_err)? {
        let file = entry.map_err(io_err)?.path();
        let is_policy = file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "yaml" | "yml" | "json"));
        if is_policy && file.is_file() {
            files.push(file);
        }
    }
    files.sort();
    Ok(files)
}

/// Parses every YAML document in `source` (JSON is valid YAML) as a policy,
/// skipping empty documents.
fn parse_policies(source: &str) -> Result<Vec<ValidatingPolicy>, serde_yaml_ng::Error> {
    let mut policies = Vec::new();
    for document in serde_yaml_ng::Deserializer::from_str(source) {
        let value = serde_yaml_ng::Value::deserialize(document)?;
        if !value.is_null() {
            policies.push(serde_yaml_ng::from_value(value)?);
        }
    }
    Ok(policies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICIES: &str = r"
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: max-replicas
spec:
  validations:
    - expression: object.spec.replicas <= 5
---
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: broken
spec:
  validations:
    - expression: object.missing.field
";

    fn provider() -> Provider {
        let policies = parse_policies(POLICIES)
            .unwrap()
            .iter()
            .map(|p| Compiler::compile(p).unwrap())
            .collect();
        Provider::new(policies)
    }

    #[test]
    fn parses_multi_document_yaml() {
        let names: Vec<_> = provider()
            .policies
            .iter()
            .map(|p| p.name().to_owned())
            .collect();
        assert_eq!(names, ["max-replicas", "broken"]);
    }

    #[test]
    fn report_reflects_each_policy() {
        let report = provider().evaluate(&json!({ "spec": { "replicas": 7 } }));
        assert!(!report.allowed);
        assert_eq!(report.results[0].outcome, Outcome::Fail);
        assert!(matches!(report.results[1].outcome, Outcome::Error { .. }));
    }
}
