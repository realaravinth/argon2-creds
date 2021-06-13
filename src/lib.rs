//! Argon2-Creds provides abstractions over credential management and cuts down on boilerplate code
//! required to implement authenticatin
//!
//! ## Example
//!
//! 1. The easiest way to use this crate is with the default configuration. See `Default`
//! implementation for the default configuration.
//!
//! ```rust
//!     use argon2_creds::Config;
//!     let config = Config::default();
//!
//!     let password = "ironmansucks";
//!     let hash = config.password(password).unwrap();
//!
//!     // email validation
//!     config.email("batman@we.net").unwrap();
//!     
//!     // process username
//!     let username = config.username("Realaravinth").unwrap(); // process username
//!     
//!     // generate hash
//!     let hash = config.password(password).unwrap();
//!
//!     assert_eq!(username, "realaravinth");
//!     assert!(Config::verify(&hash, password).unwrap(), "verify hahsing");
//! ```
//!
//! 2. To gain fine-grained control over how credentials are managed, consider using
//!    [ConfigBuilder]:
//!
//!```rust
//!     use argon2_creds::{ConfigBuilder, PasswordPolicy, Config};
//!
//!     let config = ConfigBuilder::default()
//!         .username_case_mapped(false)
//!         .profanity(true)
//!         .blacklist(false)
//!         .password_policy(PasswordPolicy::default())
//!         .build()
//!         .unwrap();
//!
//!     let password = "ironmansucks";
//!     let hash = config.password(password).unwrap();
//!
//!     // email validation
//!     config.email("batman@we.net").unwrap();
//!     
//!     // process username
//!     let username = config.username("Realaravinth").unwrap(); // process username
//!     
//!     // generate hash
//!     let hash = config.password(password).unwrap();
//!
//!     assert_eq!(username, "realaravinth");
//!     assert!(Config::verify(&hash, password).unwrap(), "verify hahsing");
//!```
//!
//! ## Documentation & Community Resources
//!
//! In addition to this API documentation, other resources are available:
//! * [Examples](https://github.com/realaravinth/argon2-creds/)
//!
//! To get started navigating the API docs, you may consider looking at the following pages first:
//!
//! * [Config]: This struct is the entry point to `argon2_creds`
//!
//! * [CredsError]: This module provides essential types for errors that can occour during
//! credential processing
//!
//! ## Features
//!
//! * [rust-argon2](https://crates.io/rust-argon2)-based password hashing
//! * PRECIS Framework [UsernameCaseMapped](https://tools.ietf.org/html/rfc8265#page-7)
//! * Keep-alive and slow requests handling
//! * Profanity filter based off of
//! [List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words](https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words)
//! * Problamatic usernames filter based off of
//! [The-Big-Username-Blacklist](https://github.com/marteinn/The-Big-Username-Blacklist)
//! * Email validation using [validator](https://crates.io/validator)

pub mod config;
pub mod errors;
mod filters;

pub use crate::config::{Config, ConfigBuilder, PasswordPolicy, PasswordPolicyBuilder};
pub use crate::errors::{CredsError, CredsResult};
