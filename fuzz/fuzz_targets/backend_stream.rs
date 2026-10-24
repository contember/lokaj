//! The server stream inspector over arbitrary bytes delivered in arbitrary chunks. Whatever it
//! forwards must be a subsequence of what it consumed, and it never reads past its input.
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use lokaj::protocol::FrontendMessage;
use lokaj::relay::{BackendStream, Relay};
use lokaj::server::Params;

fuzz_target!(|input: (Vec<u8>, Vec<u8>)| {
    let (data, cuts) = input;
    let mut relay = Relay::new();
    for _ in 0..4 {
        let _ = relay.on_frontend(&FrontendMessage::Query { sql: "select 1" });
    }
    let mut stream = BackendStream::new();
    let mut params = Params::default();
    let mut buffered = BytesMut::new();
    let mut out = BytesMut::new();
    let mut fed = 0;
    let mut consumed = 0;
    for cut in cuts.iter().map(|&c| c as usize + 1).chain(std::iter::once(data.len())) {
        let end = (fed + cut).min(data.len());
        buffered.extend_from_slice(&data[fed..end]);
        fed = end;
        let before = buffered.len();
        let result = stream.feed(&mut buffered, &mut out, &mut relay, &mut params);
        consumed += before - buffered.len();
        assert!(out.len() <= consumed);
        if result.is_err() || fed == data.len() {
            break;
        }
    }
});
