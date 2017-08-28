#[macro_use]
extern crate error_chain;
extern crate pretty_env_logger;
extern crate tss_sapi;

use tss_sapi::*;

include!("tcti.rsinclude");

quick_main!(run);

fn show_nv_area(nv: &NvRamArea) {
    println!("NVRAM index      : 0x{:08X} ({})", nv.index, nv.index);
    println!("Size             : {} (0x{:X})", nv.size, nv.size);
    println!("Hash algo        : {:?} (0x{:02X})",
             nv.hash,
             nv.hash as u16);
    println!("Auth policy      : {}", "FIXME: unknown");
    println!("Attributes       :");
    println!("  PPREAD         : {}", nv.attrs.ppread);
    println!("  PPWRITE        : {}", nv.attrs.ppwrite);
    println!("  OwnerRead      : {}", nv.attrs.owner_read);
    println!("  OwnerWrite     : {}", nv.attrs.owner_write);
    println!("  AuthRead       : {}", nv.attrs.auth_read);
    println!("  AuthWrite      : {}", nv.attrs.auth_write);
    println!("  PolicyRead     : {}", nv.attrs.policy_read);
    println!("  PolicyWrit     : {}", nv.attrs.policy_write);
    println!("  PolicyDelete   : {}", nv.attrs.policy_write);
    println!("  ReadLocked     : {}", nv.attrs.read_locked);
    println!("  WriteLocked    : {}", nv.attrs.write_locked);
    println!("  Written        : {}", nv.attrs.written);
    println!("  WriteAll       : {}", nv.attrs.write_all);
    println!("  WriteDefine    : {}", nv.attrs.write_define);
    println!("  ReadSTClear    : {}", nv.attrs.read_stclear);
    println!("  WriteSTClear   : {}", nv.attrs.write_stclear);
    println!("  ClearSTClear   : {}", nv.attrs.clear_stclear);
    println!("  GlobalLock     : {}", nv.attrs.global_lock);
    println!("  NoDA           : {}", nv.attrs.no_da);
    println!("  Orderly        : {}", nv.attrs.orderly);
    println!("  PlatformCreate : {}", nv.attrs.platform_create);
}

fn run() -> Result<()> {

    pretty_env_logger::init().unwrap();

    // use function from tcti.rs
    let ctx = open_context()?;

    // set the TPM owner auth
    //ctx.set_secret(Secret::Key(b"owner-auth"))?;

    // load the NVRAM index we are interested in
    let index = 0x1c00002;
    let nv_data = NvRamArea::get(&ctx, index)
        .chain_err(|| format!("Failed to read NVRAM area at 0x{:08X}", index))?;

    show_nv_area(&nv_data);

    Ok(())
}
