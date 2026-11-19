#![no_main]
use libfuzzer_sys::fuzz_target;
use jay_squad_sec::telemetry::parse_proc_net_tcp;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 { return; }
    let input = String::from_utf8_lossy(data);
    let _ = parse_proc_net_tcp(&input);
});
