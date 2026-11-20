use cel::Program;
use cel::common::traits::Indexer;
use cel::common::types::{CelString, Kind, Type};
use cel::common::value::{CowVal, Val};
use cel::{Context, ExecutionError};
use kube_cel::cel;
use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

pub static VARIABLES_TYPE: Type = Type::simple_type(Kind::Opaque, "kyverno.variables");

/// Variables represents that type that will inform the CEL compiler what it should do
/// when it encounters variables.x. By definition the compiler will expect this to be
/// a field access. We want it to be "execute the expression that defines the variable"
#[derive(Clone)]
pub(crate) struct Variables {
    progs: Arc<BTreeMap<String, Program>>,
    base: Arc<Context<'static, 'static>>,
    /// Keep track of variables referenced in the execution stack so two variables can't reference
    /// eachother in an infinite loop.
    in_progress: Arc<[String]>,
}

impl Variables {
    pub(crate) fn new(
        progs: Arc<BTreeMap<String, Program>>,
        base: Arc<Context<'static, 'static>>,
    ) -> Self {
        Variables {
            progs,
            base,
            in_progress: Arc::from([]),
        }
    }
}

impl std::fmt::Debug for Variables {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.progs.keys()).finish()
    }
}

/// Any type that gets registered into the CEL environment must implement this trait. Which
/// At eval time converts the type to a CEL any (ref.Val in go).
impl Val for Variables {
    fn get_type(&self) -> &Type {
        &VARIABLES_TYPE
    }

    fn cel_type() -> &'static Type {
        &VARIABLES_TYPE
    }

    /// There will only be a single instance of that type anyways
    fn equals(&self, _other: &dyn Val) -> bool {
        false
    }

    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }

    /// Return a reference to an `Indexer` from a reference to `Val`. Where the
    /// source reference has a lifetime 'b, and the original object isn't allowed to
    /// contain references that life for longer than 'v. In our case, we don't store
    /// references in `Variables` and hence 'v is 'static.
    fn as_indexer<'b, 'v>(&'b self) -> Option<&'b (dyn Indexer + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn into_indexer<'v>(self: Box<Self>) -> Option<Box<dyn Indexer + 'v>>
    where
        Self: 'v,
    {
        Some(self)
    }
}

impl Indexer for Variables {
    fn get<'b, 'v>(&'b self, idx: &dyn Val) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        // The key passed to get is Val (ref.Val) in go, cast it to a string
        let key =
            idx.downcast_ref::<CelString>()
                .ok_or_else(|| ExecutionError::UnexpectedType {
                    got: idx.get_type().name().into(),
                    want: "string".into(),
                })?;

        let prog = self
            .progs
            .get(key.inner())
            .ok_or_else(|| ExecutionError::NoSuchKey(Arc::new(key.inner().to_owned())))?;

        // Ensure that we did't try to access this before in the same evaluation chain
        if self.in_progress.iter().any(|v| v == key.inner()) {
            return Err(ExecutionError::function_error(
                "variables",
                "cyclic variable reference",
            ));
        }

        // The copy of the variables object we will be passing in the context to evaluate the variable
        // to enable variables to reference each other
        let mut child = self.clone();

        // Combine the existing in_progress with a new iterator containing only `key`
        child.in_progress = self
            .in_progress
            .iter()
            .cloned()
            .chain(std::iter::once(key.inner().to_owned()))
            .collect();

        let mut scope = self.base.new_inner_scope();
        scope.add_variable_as_val("variables", Box::new(child));
        let ret_val = prog.execute(&scope)?;

        Ok(CowVal::Owned(ret_val.try_into().unwrap()))
    }

    fn steal<'v>(self: Box<Self>, idx: &dyn Val) -> Result<Box<dyn Val + 'v>, ExecutionError>
    where
        Self: 'v,
    {
        self.get(idx).map(CowVal::into_owned)
    }
}
