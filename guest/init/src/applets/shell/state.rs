//! Shell state management.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub(super) struct Shell {
    pub(super) last_status: i32,
    pub(super) interactive: bool,
    pub(super) should_exit: bool,
    pub(super) exit_code: i32,
    pub(super) variables: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) aliases: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) positional_params: Vec<Vec<u8>>,
}

impl Shell {
    pub(super) fn new(interactive: bool) -> Self {
        Shell {
            last_status: 0,
            interactive,
            should_exit: false,
            exit_code: 0,
            variables: BTreeMap::new(),
            aliases: BTreeMap::new(),
            positional_params: Vec::new(),
        }
    }

    pub(super) fn set_var(&mut self, name: &[u8], value: &[u8]) {
        self.variables.insert(name.to_vec(), value.to_vec());
    }

    pub(super) fn get_var(&self, name: &[u8]) -> Option<&[u8]> {
        self.variables.get(name).map(|v| v.as_slice())
    }

    pub(super) fn get_positional(&self, index: usize) -> Option<&[u8]> {
        self.positional_params.get(index).map(|v| v.as_slice())
    }

    pub(super) fn set_positional_params(&mut self, script_name: &[u8], args: &[&[u8]]) {
        self.positional_params.clear();
        self.positional_params.push(script_name.to_vec());
        for arg in args {
            self.positional_params.push(arg.to_vec());
        }
    }

    pub(super) fn param_count(&self) -> usize {
        if self.positional_params.is_empty() {
            0
        } else {
            self.positional_params.len() - 1
        }
    }
}
