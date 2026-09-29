// SPDX-License-Identifier: CC-BY-NC-SA-4.0
#![no_main]

use kagi_object_store::wire::validate_frame_lengths;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    let metadata = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let body = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let max_metadata = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let max_body = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;

    if let Ok((metadata_size, body_size)) =
        validate_frame_lengths(metadata, body, max_metadata, max_body)
    {
        assert!(metadata_size <= max_metadata);
        assert!(body_size <= max_body);
        assert_eq!(metadata_size as u64, metadata);
        assert_eq!(body_size as u64, body);
    }
});
