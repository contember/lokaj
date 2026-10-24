//! Frontend message framing and parsing, fed through the relay state machine.
#![no_main]

use libfuzzer_sys::fuzz_target;
use lokaj::protocol::{frame_at, parse_frontend};
use lokaj::relay::Relay;

fuzz_target!(|data: &[u8]| {
    let mut relay = Relay::new();
    let mut rest = data;
    while let Ok(Some((tag, len))) = frame_at(rest, 1 << 20) {
        let Ok(msg) = parse_frontend(tag, &rest[5..len]) else {
            break;
        };
        if relay.on_frontend(&msg).is_err() {
            break;
        }
        rest = &rest[len..];
    }
});
