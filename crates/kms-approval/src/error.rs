//! Approval Error Types

use thiserror::Error;

/// Approval-related errors
#[derive(Error, Debug)]
pub enum ApprovalError {
    #[error("approval request not found")]
    RequestNotFound,

    #[error("approval request already completed")]
    RequestAlreadyCompleted,

    #[error("approval request expired")]
    RequestExpired,

    #[error("user has already voted on this request")]
    AlreadyVoted,

    #[error("not authorized to perform this action")]
    NotAuthorized,

    #[error("self-approval is not allowed")]
    SelfApproval,

    #[error("invalid approval configuration: {0}")]
    InvalidConfig(String),

    #[error("operation requires approval: {0}")]
    OperationRequiresApproval(String),

    #[error("approval threshold not reached")]
    ThresholdNotReached,

    #[error("approval workflow error: {0}")]
    WorkflowError(String),
}

pub type Result<T> = std::result::Result<T, ApprovalError>;
