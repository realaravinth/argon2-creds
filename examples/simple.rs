/* The easiest way to use this crate is with the default configuration.
 * See `Default` implementation for the default configuration.
 */

use argon2_creds::Config;

fn main() {
    let config = Config::default();

    let password = "ironmansucks";

    // email validation
    config.email("batman@we.net").unwrap();

    // process username
    let username = config.username("Realaravinth").unwrap(); // process username

    // generate hash
    let hash = config.password(password).unwrap();

    assert_eq!(username, "realaravinth");
    assert!(Config::verify(&hash, password).unwrap(), "verify hashing");
}
