use derive_builder::Builder;
use validator::Validate;
use validator_derive::Validate;

use crate::errors::*;
use crate::filters::{beep, filter, forbidden};

/// Credential management configuration
#[derive(Clone, Builder)]
pub struct Config {
    /// activates profanity filter. Default `false`
    #[builder(default = "false")]
    profanity: bool,
    /// activates blacklist filter. Default `true`
    #[builder(default = "true")]
    blacklist: bool,
    /// activates username_case_mapped filter. Default `true`
    #[builder(default = "true")]
    username_case_mapped: bool,
    /// activates profanity filter. Default `false`
    #[builder(default = "PasswordPolicyBuilder::default().build().unwrap()")]
    password_policy: PasswordPolicy,
}

impl PasswordPolicyBuilder {
    fn validate(&self) -> Result<(), String> {
        if self.min > self.max {
            Err("Configuration error: Password max length shorter than min length".to_string())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct PasswordPolicy {
    /// See [argon2 config][argon2::Config]
    #[builder(default = "argon2::Config::default()")]
    argon2: argon2::Config<'static>,
    /// minium password length
    #[builder(default = "8")]
    min: usize,
    /// maximum password length(to protect against DoS attacks)
    #[builder(default = "64")]
    max: usize,
    /// salt length in password hashing
    #[builder(default = "32")]
    salt_length: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicyBuilder::default().build().unwrap()
    }
}

#[derive(Validate)]
struct Email {
    #[validate(email)]
    pub email: String,
}

impl Default for Config {
    fn default() -> Self {
        ConfigBuilder::default().build().unwrap()
    }
}

impl Config {
    /// Mormalises, converts to lowercase and applies filters to the username
    pub fn username(&self, username: &str) -> CredsResult<String> {
        use ammonia::clean;
        use unicode_normalization::UnicodeNormalization;

        let clean_username = clean(username)
            .to_lowercase()
            .nfc()
            .collect::<String>()
            .trim()
            .to_owned();
        self.validate_username(&clean_username)?;
        Ok(clean_username)
    }

    /// Checks if input is an email
    pub fn email(&self, email: Option<&str>) -> CredsResult<()> {
        if let Some(email) = email {
            let email = Email {
                email: email.trim().to_owned(),
            };
            email.validate()?;
        }
        Ok(())
    }

    fn validate_username(&self, username: &str) -> CredsResult<()> {
        if self.username_case_mapped {
            filter(&username)?;
        }
        if self.blacklist {
            forbidden(&username)?;
        }
        if self.profanity {
            beep(&username)?;
        }
        Ok(())
    }

    /// Generate hash for passsword
    pub fn password(&self, password: &str) -> CredsResult<String> {
        use argon2::hash_encoded;
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        let length = password.len();

        if self.password_policy.min > length {
            return Err(CredsError::PasswordTooShort);
        }

        if self.password_policy.max < length {
            return Err(CredsError::PasswordTooLong);
        }

        let mut rng = thread_rng();
        let salt: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(self.password_policy.salt_length)
            .collect();

        Ok(hash_encoded(
            password.as_bytes(),
            salt.as_bytes(),
            &self.password_policy.argon2,
        )?)
    }

    /// Verify password against hash
    pub fn verify(hash: &str, password: &str) -> CredsResult<bool> {
        let status = argon2::verify_encoded(hash, password.as_bytes())?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_works() {
        let config = Config::default();
        assert!(!config.profanity);
        assert!(config.blacklist);
        assert!(config.username_case_mapped);
        assert_eq!(config.password_policy.salt_length, 32);

        let config = ConfigBuilder::default()
            .username_case_mapped(false)
            .profanity(true)
            .blacklist(false)
            .password_policy(PasswordPolicy::default())
            .build()
            .unwrap();

        assert!(config.profanity);
        assert!(!config.blacklist);
        assert!(!config.username_case_mapped);
    }

    #[test]
    fn creds_email_err() {
        let config = ConfigBuilder::default()
            .username_case_mapped(false)
            .profanity(true)
            .blacklist(false)
            .password_policy(PasswordPolicy::default())
            .build()
            .unwrap();

        assert_eq!(
            config.email(Some("sdfasdf".into())),
            Err(CredsError::NotAnEmail)
        );
    }

    #[test]
    fn utils_create_new_organisation() {
        let password = "somepassword";
        let config = Config::default();

        config.email(Some("batman@we.net")).unwrap();
        let username = config.username("Realaravinth").unwrap();
        let hash = config.password(password).unwrap();

        assert_eq!(username, "realaravinth");

        assert!(Config::verify(&hash, password).unwrap(), "verify hahsing");
    }

    #[test]
    fn utils_create_new_profane_organisation() {
        let config = ConfigBuilder::default()
            .username_case_mapped(false)
            .profanity(true)
            .blacklist(false)
            .password_policy(PasswordPolicy::default())
            .build()
            .unwrap();

        let username_err = config.username("fuck");

        assert_eq!(username_err, Err(CredsError::ProfainityError));
    }

    #[test]
    fn utils_create_new_forbidden_organisation() {
        let config = Config::default();
        let forbidden_err = config.username("htaccessasnc");

        assert_eq!(forbidden_err, Err(CredsError::BlacklistError));
    }

    #[test]
    fn password_length_check() {
        let min_max_error = PasswordPolicyBuilder::default().min(50).max(10).build();

        assert!(min_max_error.is_err());

        let config = ConfigBuilder::default()
            .password_policy(
                PasswordPolicyBuilder::default()
                    .min(5)
                    .max(10)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let too_short_err = config.password("a");
        let too_long_err = config.password("asdfasdfasdf");

        assert_eq!(too_short_err, Err(CredsError::PasswordTooShort));
        assert_eq!(too_long_err, Err(CredsError::PasswordTooLong));
    }
}
