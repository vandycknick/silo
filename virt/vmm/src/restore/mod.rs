//! ADR 0021 clone restore and ADR 0023 same-machine wake.
//!
//! Wake uses `RestoreAuthority::Hibernation` with four inherited read-only
//! saved descriptors and the original writable disk descriptors from the launch.
//! The worker rechecks reboot-stable file facts before construction and before
//! reporting prepared. Native owned-file restore keeps RAM privately mapped and
//! retains it as the byte baseline, without an identified stream map.
//!
//! The manager polls `GetRestorePrepared`, durably consumes the exact save and
//! binds the RAM roots to the new launch, then sends `AuthorizeConsume`.
//! Until that exact authorization, neither generation activation nor any guest
//! instruction is allowed. `AbandonRestore`, cancellation, parent loss and the
//! original startup deadline all end an unauthorized wake without guest shutdown.
//! A valid authorization enters the existing fresh-generation, agent activation,
//! listener binding, thaw and exposure sequence with purpose `SameMachine`.
//!
//! Wake startup errors carry `WakeFailureBoundary::{PreConsume, PostConsume}`;
//! service teardown force-stops and reaps before returning them. Unlike clone
//! activation failures, failed wakes never remain parked as `ActivationFailed`.
//! The terminal startup/exit diagnostic says "before consume" or "after consume".
//! The manager also knows its own durable consume decision: losing an
//! authorization reply never grants permission to reuse a consumed save.
//! Clone restore has no consume gate and retains its original failure behavior.
pub(crate) mod activation;
pub(crate) mod inputs;
pub(crate) mod inspect;
