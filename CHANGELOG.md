## 0.2.1

### Added

- `Config::init`: explicit call to init lazy-init filters.

### Changed:

-`Config::email` now takes a `&str` instead of `Option<&str>`

- Blacklist and profanity matches against exact strings **only**. This
  means, `.htaccess` is illegal while `.htaccessme` is legal.

## 0.2.0

### Added

- minimum and maximum password length

## 0.1.0

### Added:

- password configuration
- UsernameCaseMapped filter
- Abusive words filter
- filter for words that might cause security issues
