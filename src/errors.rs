use std::convert::From;

use derive_more::{Display, Error};
use validator::ValidationErrors;

/// Errors that can occur when processing credentials
#[derive(Debug, PartialEq, Display, Clone, Error)]
#[cfg(not(tarpaulin_include))]
pub enum CredsError {
    /// when the value passed contains profainity
    #[display(fmt = "the value you passed contains profainity")]
    ProfainityError,

    /// when the value passed contains characters not present
    /// in [UsernameCaseMapped](https://tools.ietf.org/html/rfc8265#page-7)
    /// profile
    #[display(fmt = "username_case_mapped violation")]
    UsernameCaseMappedError,

    /// when the value passed contains blacklisted words
    /// see [blacklist](https://github.com/shuttlecraft/The-Big-Username-Blacklist)
    #[display(fmt = "contains blacklisted words")]
    BlacklistError,

    /// email validation error
    #[display(fmt = "The value passed in not an email")]
    NotAnEmail,

    /// password too short
    #[display(fmt = "Password too short")]
    PasswordTooShort,

    /// password too long
    #[display(fmt = "Password too long")]
    PasswordTooLong,

    /// Errors from argon2
    #[display(fmt = "{}", _0)]
    Argon2Error(argon2::Error),
}

impl From<argon2::Error> for CredsError {
    fn from(e: argon2::Error) -> CredsError {
        CredsError::Argon2Error(e)
    }
}

impl From<ValidationErrors> for CredsError {
    fn from(_: ValidationErrors) -> CredsError {
        CredsError::NotAnEmail
    }
}

pub type CredsResult<V> = std::result::Result<V, crate::errors::CredsError>;
