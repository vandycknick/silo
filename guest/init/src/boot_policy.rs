//! The initramfs decision before handing PID 1 to the image or agent.

use crate::boot_args::Rescue;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Handoff,
    Rescue,
    PowerOff,
}

pub fn action(rescue: Option<Rescue>, failed: bool) -> Action {
    match (rescue, failed) {
        (Some(Rescue::Always), _) | (Some(Rescue::OnFailure), true) => Action::Rescue,
        (_, true) => Action::PowerOff,
        (_, false) => Action::Handoff,
    }
}

#[cfg(test)]
mod tests {
    use crate::boot_args::Rescue;
    use crate::boot_policy::{action, Action};

    #[test]
    fn every_boot_result_and_rescue_policy_has_an_explicit_action() {
        for (rescue, failed, expected) in [
            (None, false, Action::Handoff),
            (None, true, Action::PowerOff),
            (Some(Rescue::OnFailure), false, Action::Handoff),
            (Some(Rescue::OnFailure), true, Action::Rescue),
            (Some(Rescue::Always), false, Action::Rescue),
            (Some(Rescue::Always), true, Action::Rescue),
        ] {
            assert_eq!(
                action(rescue, failed),
                expected,
                "{rescue:?}, failed={failed}"
            );
        }
    }
}
