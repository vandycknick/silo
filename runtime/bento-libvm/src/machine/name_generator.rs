use crate::machine::reference::validate_machine_name;
use crate::LibVmError;

const ADJECTIVES: &[&str] = &[
    "amber",
    "brave",
    "bright",
    "calm",
    "cedar",
    "clever",
    "cosmic",
    "crisp",
    "daring",
    "dawn",
    "eager",
    "ember",
    "fabled",
    "fleet",
    "gentle",
    "golden",
    "harbor",
    "hidden",
    "honest",
    "jolly",
    "lively",
    "lunar",
    "mellow",
    "mighty",
    "nimble",
    "noble",
    "patient",
    "plucky",
    "proud",
    "quiet",
    "rapid",
    "ready",
    "remote",
    "river",
    "silver",
    "steady",
    "sunny",
    "swift",
    "tidy",
    "valiant",
    "velvet",
    "vivid",
    "wandering",
    "warm",
    "wild",
    "winter",
    "wise",
    "zesty",
];

const NOUNS: &[&str] = &[
    "badger", "beacon", "bison", "branch", "brook", "comet", "coyote", "cricket", "drift",
    "falcon", "fern", "forge", "gopher", "grove", "harrier", "heron", "island", "juniper", "koala",
    "lantern", "lark", "maple", "meadow", "meteor", "otter", "panda", "pioneer", "quartz",
    "raccoon", "raven", "sable", "salmon", "sparrow", "spruce", "summit", "tundra", "valley",
    "violet", "walrus", "willow", "wombat", "yak", "zephyr", "zircon", "anchor", "cinder",
    "glacier", "orchid",
];

pub(crate) fn generate_machine_name() -> Result<String, LibVmError> {
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy)
        .map_err(|_| LibVmError::MachineNameGenerationFailed { attempts: 0 })?;
    name_from_entropy(u64::from_le_bytes(entropy))
}

fn name_from_entropy(entropy: u64) -> Result<String, LibVmError> {
    let adjective = choose_word(ADJECTIVES, entropy)?;
    let noun = choose_word(NOUNS, entropy.rotate_left(21))?;
    let suffix = u16::try_from(entropy.rotate_left(42) & 0xffff)
        .map_err(|_| LibVmError::MachineNameGenerationFailed { attempts: 0 })?;
    let name = format!("{adjective}-{noun}-{suffix:04x}");
    validate_machine_name(&name)?;
    Ok(name)
}

fn choose_word(words: &[&'static str], entropy: u64) -> Result<&'static str, LibVmError> {
    let word_count = u64::try_from(words.len())
        .map_err(|_| LibVmError::MachineNameGenerationFailed { attempts: 0 })?;
    if word_count == 0 {
        return Err(LibVmError::MachineNameGenerationFailed { attempts: 0 });
    }
    let index = usize::try_from(entropy % word_count)
        .map_err(|_| LibVmError::MachineNameGenerationFailed { attempts: 0 })?;
    words
        .get(index)
        .copied()
        .ok_or(LibVmError::MachineNameGenerationFailed { attempts: 0 })
}

#[cfg(test)]
mod tests {
    use crate::machine::reference::{MachineRef, MachineRefKind};

    use super::{generate_machine_name, name_from_entropy};

    #[test]
    fn generated_names_are_valid_machine_names() {
        for entropy in [0, 1, 42, u64::MAX, 0x1234_5678_9abc_def0] {
            let name = name_from_entropy(entropy).expect("generate deterministic name");
            assert_eq!(name, name.to_ascii_lowercase());
            assert!(name.contains('-'));

            let machine_ref = MachineRef::parse(name.clone()).expect("generated name parses");
            assert_eq!(machine_ref.kind(), &MachineRefKind::Name(name));
        }
    }

    #[test]
    fn random_name_generator_returns_valid_name() {
        let name = generate_machine_name().expect("generate random name");
        let machine_ref = MachineRef::parse(name.clone()).expect("generated name parses");

        assert_eq!(machine_ref.kind(), &MachineRefKind::Name(name));
    }
}
