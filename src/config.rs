use derive_builder::Builder;
use validator::Validate;
use validator_derive::Validate;

use crate::errors::*;
use crate::filters::{beep, filter, forbidden};

#[derive(Clone, Builder)]
pub struct Config {
    profanity: bool,
    blacklist: bool,
    username_case_mapped: bool,
    salt_length: usize,
    argon2: argon2::Config<'static>,
}

#[derive(Validate)]
struct Email {
    #[validate(email)]
    pub email: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            /// profanity filter
            profanity: false,
            /// blacklist filter
            blacklist: true,
            /// UsernameCaseMapped filter
            username_case_mapped: true,
            /// salt length
            salt_length: 32,
            /// argon2 configuration, see argon2::Processor for more information
            argon2: argon2::Config::default(),
        }
    }
}

impl Config {
    /// process username
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

    /// process email
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

    /// generate hash for password
    pub fn password(&self, password: &str) -> CredsResult<String> {
        use argon2::hash_encoded;
        use rand::distributions::Alphanumeric;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        let salt: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(self.salt_length)
            .collect();

        Ok(hash_encoded(
            password.as_bytes(),
            salt.as_bytes(),
            &self.argon2,
        )?)
    }

    /// verify password against hash
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
        assert_eq!(config.salt_length, 32);

        let new_length = 50;

        let config = ConfigBuilder::default()
            .salt_length(new_length)
            .username_case_mapped(false)
            .profanity(true)
            .blacklist(false)
            .argon2(argon2::Config::default())
            .build()
            .unwrap();

        assert!(config.profanity);
        assert!(!config.blacklist);
        assert!(!config.username_case_mapped);
        assert_eq!(config.salt_length, new_length);
    }

    #[test]
    fn creds_email_err() {
        let config = ConfigBuilder::default()
            .salt_length(50)
            .username_case_mapped(false)
            .profanity(true)
            .blacklist(false)
            .argon2(argon2::Config::default())
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
            .salt_length(50)
            .username_case_mapped(false)
            .profanity(true)
            .blacklist(false)
            .argon2(argon2::Config::default())
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
}
