<div align="center">
  <h1>Argon2-Creds</h1>
  <p>
    <strong>Argon2-Creds provides a convenient abstractions for managing
	credentials</strong>
  </p>
  <p>

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
