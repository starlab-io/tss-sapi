#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use tss_sapi::*;

// can't use modules in examples
include!("tcti.rsinclude");

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
    ctx.take_ownership(tss_sapi::HierarchyAuth::Owner, "test123")
        .chain_err(|| "Unable to set Owner Auth")?;
    ctx.take_ownership(tss_sapi::HierarchyAuth::Endorsement, "test123")
        .chain_err(|| "Unable to set Endorsement Auth")?;
    ctx.take_ownership(tss_sapi::HierarchyAuth::Lockout, "test123")
        .chain_err(|| "Unable to set Lockout Auth")
}
