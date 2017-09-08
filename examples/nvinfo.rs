#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use tss_sapi::*;

quick_main!(run);

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    let ctx = utils::open_context_from_env()?;

    // load the NVRAM index we are interested in
    let index = 0x1500016;
    let nv_data = NvRamArea::get(&ctx, index)
        .chain_err(|| format!("Failed to read NVRAM area at 0x{:08X}", index))?;

    println!("{}", nv_data);

    Ok(())
}
