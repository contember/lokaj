//! Startup-phase packets: SSLRequest, GSSENCRequest, CancelRequest and StartupMessage.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lokaj::protocol::{parse_startup_packet, startup_packet_len};

fuzz_target!(|data: &[u8]| {
    if data.len() >= 4 {
        let _ = startup_packet_len([data[0], data[1], data[2], data[3]]);
    }
    let _ = parse_startup_packet(data);
});
