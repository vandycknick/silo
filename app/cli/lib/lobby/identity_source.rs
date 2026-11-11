use std::sync::Arc;

use crate::lobby::caller::Resolve;

/// Binds the trusted transport address to a resolver, never a claimed username.
pub(crate) type IdentitySource = Arc<dyn Fn(&str) -> Resolve + Send + Sync>;
