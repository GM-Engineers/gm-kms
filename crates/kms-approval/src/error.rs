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

    /// The approver's role level is below the level the operation requires.
    ///
    /// Without this check a low-privilege approver could contribute a vote
    /// toward a high-privilege quorum (e.g. a read-only key voting on a
    /// key-export request that requires triple approval).
    #[error("approver role level is insufficient for this operation")]
    InsufficientApprovalLevel,

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
