#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

mod tcti;

use tcti::open_context;
use tss_sapi::*;

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    // use function from tcti.rs
    let ctx = open_context()?;

    // check if the TPM is already owned
    if ctx.is_owned()? {
        println!("The TPM is already owned");
        return Ok(());
    }

    // attempt to take ownership of the TPM with the password 'test123'
    ctx.take_ownership("test123")
}
