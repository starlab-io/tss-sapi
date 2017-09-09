#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use std::io::Read;
use tss_sapi::*;

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    let mut ctx = utils::open_context_from_env()?;
    // set the current owner password
    ctx.password("test123");

    // the NVRAM index
    let index = 0x1500016;

    let mut nv_data = NvRamArea::get(&ctx, index)
        .chain_err(|| format!("Failed to get NVRAM area at 0x{:08X}", index))?;

    // where to store the data
    let mut buf = Vec::new();

    // read as much as we can
    nv_data.read_to_end(&mut buf)?;

    println!("{:?}", buf);

    Ok(())
}
