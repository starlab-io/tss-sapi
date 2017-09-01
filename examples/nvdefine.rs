#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use tss_sapi::*;

include!("tcti.rsinclude");

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    // use function from tcti.rs
    let ctx = open_context()?;

    // create the NVRAM index, along with its data
    let index = 0x00100001;
    let size = 128;
    let attrs = NvAttributes {
        owner_read: true,
        owner_write: true,
        ..Default::default()
    };

    let nv_data = NvRamArea::define(&ctx, index, size, TpmAlgorithm::SHA1, attrs)
        .chain_err(|| format!("Failed to create NVRAM area at 0x{:08X}", index))?;

    println!("{}", nv_data);

    Ok(())
}
