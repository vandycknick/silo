use eyre::Report;

#[derive(Debug)]
pub(crate) struct ExecutionExit {
    code: i32,
}

impl ExecutionExit {
    pub(crate) fn new(code: i32) -> Self {
        Self { code }
    }
}

impl std::fmt::Display for ExecutionExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "execution exited with status {}", self.code)
    }
}

impl std::error::Error for ExecutionExit {}

pub(crate) fn execution_exit_code(error: &Report) -> Option<i32> {
    error.downcast_ref::<ExecutionExit>().map(|exit| exit.code)
}

pub fn print(error: &Report, verbose: u8) {
    let causes = error
        .chain()
        .filter(|cause| !cause.is::<ExecutionExit>())
        .collect::<Vec<_>>();
    let Some(head) = causes.first() else {
        eprintln!("error: {error}");
        return;
    };

    eprintln!("{} {head}", crate::ui::error_label());

    if verbose == 0 {
        if causes.len() > 1 {
            eprintln!("\nhint: rerun with -v for more detail");
        }
        return;
    }

    for (index, cause) in causes.into_iter().skip(1).enumerate() {
        eprintln!("  {}: {cause}", index + 1);
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::{execution_exit_code, ExecutionExit};

    #[test]
    fn execution_exit_code_survives_context() {
        let error = eyre::eyre!("guest stream failed").wrap_err(ExecutionExit::new(125));

        assert_eq!(execution_exit_code(&error), Some(125));
    }
}
