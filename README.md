<div align="center">
  <h1>Argon2-Creds</h1>
  <p>
    <strong>Argon2-Creds - convenient abstractions for managing credentials</strong>
  </p>

[![Documentation](https://img.shields.io/badge/docs-master-blue)](https://realaravinth.github.io/argon2-creds/argon2_creds/index.html)
![CI (Linux)](<https://github.com/realaravinth/argon2-creds/workflows/CI%20(Linux)/badge.svg>)
[![dependency status](https://deps.rs/repo/github/realaravinth/argon2-creds/status.svg)](https://deps.rs/repo/github/realaravinth/argon2-creds)
<br />
[![codecov](https://codecov.io/gh/realaravinth/argon2-creds/branch/master/graph/badge.svg)](https://codecov.io/gh/realaravinth/argon2-creds) 

</div>

## Features
- [x] PRECIS Framework [UsernameCaseMapped](https://tools.ietf.org/html/rfc8265#page-7)
- [x] Password hashing and validation using
  [rust-argon2](https://crates.io/crates/rust-argon2)
- [x] Filters for words that might cause ambiguity. See 
[Blacklist](https://github.com/shuttlecraft/The-Big-Username-Blacklist)
- [x] Profanity filter
- [x] Email validation(Regex validation not verification)

## Usage:

Add this to your `Cargo.toml`:

```toml
argon2-creds = { version = "0.2", git = "https://github.com/realaravinth/argon2-creds" }
```

## Examples:

1. The easiest way to use this crate is with the default configuration. See `Default`
 implementation for the default configuration.

 ```rust
use argon2_creds::Config;

fn main() {
    let config = Config::default();

    let password = "ironmansucks";

    // email validation
    config.email(Some("batman@we.net")).unwrap();

    // process username
    let username = config.username("Realaravinth").unwrap(); // process username

    // generate hash
    let hash = config.password(password).unwrap();

    assert_eq!(username, "realaravinth");
    assert!(Config::verify(&hash, password).unwrap(), "verify hahsing");
}
```

2. To gain fine-grained control over how credentials are managed, consider using
    [ConfigBuilder]:

```rust
use argon2_creds::{Config, ConfigBuilder, PasswordPolicyBuilder};

fn main() {
    let config = ConfigBuilder::default()
        .username_case_mapped(false)
        .profanity(true)
        .blacklist(false)
        .password_policy(
            PasswordPolicyBuilder::default()
                .min(12)
                .max(80)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    let password = "ironmansucks";
    let hash = config.password(password).unwrap();

    // email validation
    config.email(Some("batman@we.net")).unwrap();

    // process username
    let username = config.username("Realaravinth").unwrap(); // process username

    // generate hash
    let hash = config.password(password).unwrap();

    assert_eq!(username, "realaravinth");
    assert!(Config::verify(&hash, password).unwrap(), "verify hahsing");
}
```
