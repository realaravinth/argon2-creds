pub mod errors;
mod filters;

use ammonia::clean;
use argon2::{self, Config, ThreadMode, Variant, Version};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use unicode_normalization::UnicodeNormalization;
use validator::Validate;
use validator_derive::Validate;

use errors::*;

pub use filters::{beep, filter, forbidden};

#[derive(Debug, Clone, PartialEq)]
pub struct UnvalidatedRegisterCreds {
    pub username: String,
    pub email_id: Option<String>,
    pub password: String,
}

#[derive(Debug, Default, Clone, PartialEq, Validate)]
pub struct RegisterCreds {
    pub username: String,
    #[validate(email)]
    pub email_id: Option<String>,
    pub password: String,
}

impl UnvalidatedRegisterCreds {
    pub fn process(&self) -> CredsResult<RegisterCreds> {
        let creds = RegisterCreds::default()
            .set_email(&self.email_id)?
            .set_username(&self.username)
            .validate_fields()?
            .set_password(&self.password)?
            .build();
        Ok(creds)
    }
}

impl RegisterCreds {
    pub fn set_username<'a>(&'a mut self, username: &str) -> &'a mut Self {
        self.username = clean(username)
            .to_lowercase()
            .nfc()
            .collect::<String>()
            .trim()
            .to_owned();
        self
    }

    pub fn set_email<'a>(&'a mut self, email_id: &Option<String>) -> CredsResult<&'a mut Self> {
        if let Some(email) = email_id {
            self.email_id = Some(email.trim().to_owned());
            self.validate()?;
        }
        Ok(self)
    }

    pub fn validate_fields<'a>(&'a mut self) -> CredsResult<&'a mut Self> {
        filter(&self.username)?;
        forbidden(&self.username)?;
        beep(&self.username)?;
        Ok(self)
    }

    pub fn set_password<'a>(&'a mut self, password: &str) -> CredsResult<&'a mut Self> {
        //        let config = Config {
        //            variant: Variant::Argon2i,
        //            version: Version::Version13,
        //            mem_cost: SETTINGS.password_difficulty.mem_cost,
        //            time_cost: SETTINGS.password_difficulty.time_cost,
        //            lanes: SETTINGS.password_difficulty.lanes,
        //            thread_mode: ThreadMode::Parallel,
        //            secret: &[],
        //            ad: &[],
        //            hash_length: 32,
        //        };
        let config = Config::default();

        let mut rng = thread_rng();
        let salt: String = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .map(char::from)
            .take(32)
            .collect();

        self.password = argon2::hash_encoded(password.as_bytes(), salt.as_bytes(), &config)?;
        Ok(self)
    }

    pub fn build(&mut self) -> Self {
        self.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utils_register_builer() {
        let registered_creds = RegisterCreds::default()
            .set_password("password")
            .unwrap()
            .set_username("realaravinth")
            .set_email(&Some("batman@we.net".into()))
            .unwrap()
            .validate_fields()
            .unwrap()
            .build();

        assert_eq!(registered_creds.username, "realaravinth");
        assert_eq!(registered_creds.email_id, Some("batman@we.net".into()));
    }

    #[test]
    fn utils_register_email_err() {
        let mut email_err = RegisterCreds::default()
            .set_password("password")
            .unwrap()
            .set_username("realaravinth")
            .build();
        assert_eq!(
            email_err.set_email(&Some("sdfasdf".into())),
            Err(CredsError::NotAnEmail)
        );
    }

    #[test]
    fn utils_create_new_organisation() {
        let password = "somepassword";
        let org = RegisterCreds::default()
            .set_email(&Some("batman@we.net".into()))
            .unwrap()
            .set_username("Realaravinth")
            .validate_fields()
            .unwrap()
            .set_password(password)
            .unwrap()
            .build();

        assert_eq!(org.username, "realaravinth");

        assert!(
            argon2::verify_encoded(&org.password, password.as_bytes()).unwrap(),
            "verify hahsing"
        );
    }

    #[test]
    fn utils_create_new_profane_organisation() {
        let mut profane_org = RegisterCreds::default();
        profane_org.set_username("fuck");

        assert_eq!(
            profane_org.validate_fields(),
            Err(CredsError::ProfainityError)
        );
    }

    #[test]
    fn utils_create_new_forbidden_organisation() {
        let mut forbidden_org = RegisterCreds::default()
            .set_username("htaccessasnc")
            .build();

        assert_eq!(
            forbidden_org.validate_fields(),
            Err(CredsError::BlacklistError)
        );
    }
}
