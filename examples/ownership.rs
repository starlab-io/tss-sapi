#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use tss_sapi::*;

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    // create a SAPI context and connect to the default TPM emulator
    let ctx = Context::socket(None, None)?;

    // attempt to take ownership of the TPM with the password 'test123'
    ctx.take_ownership("test123")
}
