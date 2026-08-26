use std::sync::{Arc, Mutex};

use libvm::{ExecutionControl, ExecutionSession, Machine, MachineLogStream, Runtime};

pub struct RuntimeContext {
    pub runtime: Runtime,
    pub tokio: tokio::runtime::Runtime,
}

pub struct RuntimeHandle {
    pub context: Arc<RuntimeContext>,
}

pub struct ExecutionSessionState {
    pub session: Option<ExecutionSession>,
    pub operation_in_flight: bool,
    pub closed: bool,
    pub cancellation: tokio::sync::watch::Sender<bool>,
}

impl ExecutionSessionState {
    pub fn new(session: ExecutionSession) -> Self {
        let (cancellation, _) = tokio::sync::watch::channel(false);
        Self {
            session: Some(session),
            operation_in_flight: false,
            closed: false,
            cancellation,
        }
    }
}

pub struct ExecutionHandle {
    pub context: Arc<RuntimeContext>,
    pub state: Mutex<ExecutionSessionState>,
    pub control: ExecutionControl,
}

pub struct LogState {
    pub stream: Option<MachineLogStream>,
    pub receive_in_flight: bool,
    pub closed: bool,
    pub cancellation: tokio::sync::watch::Sender<bool>,
}

pub struct LogHandle {
    pub context: Arc<RuntimeContext>,
    pub state: Mutex<LogState>,
}

pub struct StdinHandle {
    pub context: Arc<RuntimeContext>,
    pub stdin: libvm::ExecutionStdin,
}

pub struct MachineHandle {
    pub context: Arc<RuntimeContext>,
    pub machine: Machine,
}

#[repr(C)]
pub struct MachineHandleList {
    pub ptr: *mut *mut MachineHandle,
    pub len: usize,
}

impl MachineHandleList {
    pub fn from_machines(context: &Arc<RuntimeContext>, machines: Vec<Machine>) -> Self {
        let handles = machines
            .into_iter()
            .map(|machine| {
                Box::into_raw(Box::new(MachineHandle {
                    context: Arc::clone(context),
                    machine,
                }))
            })
            .collect::<Vec<_>>();
        let mut handles = handles.into_boxed_slice();
        let list = Self {
            ptr: handles.as_mut_ptr(),
            len: handles.len(),
        };
        std::mem::forget(handles);
        list
    }
}
