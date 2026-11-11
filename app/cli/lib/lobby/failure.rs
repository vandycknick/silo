use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Failure {
    pub(crate) code: Code,
    pub(crate) message: String,
    #[serde(skip)]
    pub(crate) exit: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Code {
    Usage,
    NotFound,
    Forbidden,
    Conflict,
    Limit,
    OperationFailed,
    Image,
    PendingApproval,
    Expired,
    Unavailable,
    Cancelled,
    /// The session's transport went away while an operation was observed.
    Disconnected,
}

impl Failure {
    pub(crate) fn new(code: Code, message: impl Into<String>) -> Self {
        let exit = match code {
            Code::Usage | Code::Cancelled => 2,
            Code::NotFound => 3,
            Code::Forbidden => 4,
            Code::Conflict => 5,
            Code::Limit => 6,
            Code::OperationFailed | Code::Image => 7,
            Code::PendingApproval | Code::Expired => 8,
            Code::Unavailable => 9,
            Code::Disconnected => 255,
        };
        Self {
            code,
            message: message.into(),
            exit,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

pub(crate) type Outcome<T> = Result<T, Failure>;

#[cfg(test)]
mod tests {
    use crate::lobby::failure::{Code, Failure};
    #[test]
    fn error_codes_and_serialization() {
        for (code, exit, name) in [
            (Code::Usage, 2, "usage"),
            (Code::NotFound, 3, "not_found"),
            (Code::Forbidden, 4, "forbidden"),
            (Code::Conflict, 5, "conflict"),
            (Code::Limit, 6, "limit"),
            (Code::OperationFailed, 7, "operation_failed"),
            (Code::Image, 7, "image"),
            (Code::PendingApproval, 8, "pending_approval"),
            (Code::Expired, 8, "expired"),
            (Code::Unavailable, 9, "unavailable"),
            (Code::Cancelled, 2, "cancelled"),
        ] {
            let error = Failure::new(code, "message");
            assert_eq!(error.exit, exit);
            assert_eq!(error.to_string(), "message");
            assert_eq!(
                serde_json::to_value(error).unwrap(),
                serde_json::json!({"code":name,"message":"message"})
            );
        }
    }
}
