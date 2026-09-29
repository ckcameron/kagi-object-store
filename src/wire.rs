// SPDX-License-Identifier: CC-BY-NC-SA-4.0
// Copyright (c) 2026 CK Cameron. Licensed under CC BY-NC-SA 4.0.
//! Small, pure wire-format validation helpers shared by transports and fuzzers.
//!
//! Network framing must reject oversized and non-addressable lengths before allocating.
//! Keeping these checks independent of the socket implementation makes them practical to
//! exhaustively unit-test, fuzz under libFuzzer, and run under Miri.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    MetadataTooLarge,
    BodyTooLarge,
    LengthNotAddressable,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetadataTooLarge => formatter.write_str("frame metadata exceeds configured limit"),
            Self::BodyTooLarge => formatter.write_str("frame body exceeds configured limit"),
            Self::LengthNotAddressable => {
                formatter.write_str("frame length cannot be represented on this platform")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Validate untrusted frame lengths before any allocation.
///
/// Lengths are accepted as u64 because that is what the QUIC wire header carries. Conversion
/// to usize occurs only after both configured bounds have been checked.
pub fn validate_frame_lengths(
    metadata_length: u64,
    body_length: u64,
    max_metadata_bytes: usize,
    max_body_bytes: usize,
) -> Result<(usize, usize), FrameError> {
    if metadata_length > max_metadata_bytes as u64 {
        return Err(FrameError::MetadataTooLarge);
    }
    if body_length > max_body_bytes as u64 {
        return Err(FrameError::BodyTooLarge);
    }
    let metadata_length =
        usize::try_from(metadata_length).map_err(|_| FrameError::LengthNotAddressable)?;
    let body_length = usize::try_from(body_length).map_err(|_| FrameError::LengthNotAddressable)?;
    Ok((metadata_length, body_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limits_are_allowed() {
        assert_eq!(
            validate_frame_lengths(64, 1024, 64, 1024).unwrap(),
            (64, 1024)
        );
    }

    #[test]
    fn one_byte_over_limits_is_rejected() {
        assert_eq!(
            validate_frame_lengths(65, 1, 64, 1024),
            Err(FrameError::MetadataTooLarge)
        );
        assert_eq!(
            validate_frame_lengths(1, 1025, 64, 1024),
            Err(FrameError::BodyTooLarge)
        );
    }

    #[test]
    fn huge_lengths_never_wrap() {
        assert!(validate_frame_lengths(u64::MAX, u64::MAX, 64, 1024).is_err());
    }
}
