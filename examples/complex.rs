//To gain fine-grained control over how credentials are managed, consider using ConfigBuilder:

use argon2_creds::{Config, ConfigBuilder};

fn main() {
    let config = ConfigBuilder::default()
        .salt_length(32)
        .username_case_mapped(false)
        .profanity(true)
        .blacklist(false)
        .argon2(argon2::Config::default())
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
