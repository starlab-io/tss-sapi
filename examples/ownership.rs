#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use std::env;
use tss_sapi::*;

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    let addr = env::var("TPM2TOOLS_SOCKET_ADDRESS").ok();
    let port = match env::var("TPM2TOOLS_SOCKET_PORT").ok() {
        None => None,
        Some(v) => Some(v.parse::<u16>().chain_err(|| "Unable to parse TPM2TOOLS_SOCKET_PORT")?),
    };

    // create a SAPI context and connect to the default TPM emulator
    let ctx = tss_sapi::Context::socket(addr.as_ref().map(|v| v.as_ref()), port)?;

    // check if the TPM is already owned
    if ctx.is_owned()? {
        println!("The TPM is already owned");
        return Ok(());
    }

    // attempt to take ownership of the TPM with the password 'test123'
    ctx.take_ownership("test123")
}
