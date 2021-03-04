/* To gain fine-grained control over how credentials are managed,
 * consider using ConfigBuilder:
 */

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
