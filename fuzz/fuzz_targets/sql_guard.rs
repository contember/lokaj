//! The lexical guard over arbitrary query text.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|sql: &str| {
    let _ = lokaj::sql_guard::check(sql);
});
