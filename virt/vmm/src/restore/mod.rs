//! ADR 0021 restore on the monitor side: inherited descriptor adoption, the
//! descriptor-only `inspect-restore` admission command and the activation
//! sequence that owns Restoring → Activating → Running | ActivationFailed.
pub(crate) mod activation;
pub(crate) mod inputs;
pub(crate) mod inspect;
