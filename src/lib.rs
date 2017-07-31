// Copyright 2017 Star Lab Corp.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

mod errors;

#[allow(non_snake_case, non_camel_case_types, dead_code)]
#[allow(non_upper_case_globals, improper_ctypes)]
mod sys {
    include!("bindings.rs");
}
