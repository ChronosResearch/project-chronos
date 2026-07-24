#![no_main]
use libfuzzer_sys::fuzz_target;
use chronos_net::p2p::NetworkService;

fuzz_target!(|data: &[u8]| {
    // Fuzz the broadcast_task function to ensure the underlying libp2p gossipsub
    // publisher does not panic when fed arbitrary, malformed byte arrays.
    if let Ok(mut service) = NetworkService::new() {
        let _ = service.broadcast_task(data);
    }
});
