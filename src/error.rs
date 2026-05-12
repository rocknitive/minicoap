/// Errors that can occur when building a CoAP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CoapBuildError {
    /// The provided buffer is too small to fit the message being constructed.
    BufferTooSmall,
    /// Building the payload failed after request options had already been written.
    PayloadBuildFailed,
    /// The token is longer than 8 bytes. Contains the actual length that was provided.
    TokenTooLong(usize),
    /// A payload marker (0xFF) was added but no payload data was provided.
    /// Use `no_payload()` instead of `payload()` when there is no payload.
    PayloadMarkerWithoutPayload,
    /// Options must be added in ascending order by option number.
    /// An attempt was made to add an option with a number less than or equal to the previous option.
    OptionNumberOutOfOrder,
    /// A block option value was invalid before encoding.
    InvalidBlockOption(BlockOptionError),
}

impl core::fmt::Display for CoapBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoapBuildError::BufferTooSmall => write!(f, "Buffer too small"),
            CoapBuildError::PayloadBuildFailed => write!(f, "Payload build failed"),
            CoapBuildError::TokenTooLong(len) => {
                write!(f, "Token too long (expected <= 8, got {})", len)
            }
            CoapBuildError::PayloadMarkerWithoutPayload => {
                write!(f, "Payload marker without payload")
            }
            CoapBuildError::OptionNumberOutOfOrder => write!(f, "Option number out of order"),
            CoapBuildError::InvalidBlockOption(err) => write!(f, "{}", err),
        }
    }
}

impl core::error::Error for CoapBuildError {}

/// Errors that can occur when parsing a CoAP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CoapParseError {
    /// The message buffer is too short to contain a valid CoAP message.
    /// A valid CoAP message must be at least 4 bytes (header).
    MessageTooShort,
    /// The version field contains an unknown or unsupported version number.
    /// Contains the version number that was encountered. Currently only version 1 is supported.
    UnknownVersion(u8),
    /// The token length field (TKL) contains an invalid value.
    /// Token length must be between 0 and 8 bytes. Contains the actual length that was found.
    InvalidTokenLength(usize),
    /// An option has a delta value of 15, which is reserved and invalid per RFC 7252.
    InvalidOptionDelta,
    /// An option has a length value of 15, which is reserved and invalid per RFC 7252.
    InvalidOptionLength,
    /// An empty message (code 0.00) contains data after the header, which is not allowed.
    EmptyMessageWithData,
    /// A payload marker (0xFF) was present but no payload data followed it.
    PayloadMarkerWithoutPayload,
    /// A block option contained an invalid packed value.
    InvalidBlockOption(BlockOptionError),
}

impl core::fmt::Display for CoapParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoapParseError::MessageTooShort => write!(f, "Message too short"),
            CoapParseError::UnknownVersion(v) => write!(f, "Unknown CoAP version: {}", v),
            CoapParseError::InvalidTokenLength(len) => {
                write!(f, "Invalid token length (expected 0-8, got {})", len)
            }
            CoapParseError::InvalidOptionDelta => write!(f, "Invalid option delta (15)"),
            CoapParseError::InvalidOptionLength => write!(f, "Invalid option length (15)"),
            CoapParseError::EmptyMessageWithData => {
                write!(f, "Empty message (code 0.00) contains data after header")
            }
            CoapParseError::PayloadMarkerWithoutPayload => {
                write!(f, "Payload marker present but no payload data")
            }
            CoapParseError::InvalidBlockOption(err) => write!(f, "{}", err),
        }
    }
}

impl core::error::Error for CoapParseError {}

/// Errors that can occur while validating or decoding a CoAP block option value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BlockOptionError {
    /// The block number exceeded the 20-bit limit of the CoAP block format.
    InvalidBlockNumber(u64),
    /// The packed block size exponent did not map to a valid block size.
    InvalidBlockSize,
    /// The raw block option value exceeded the allowed 3-byte encoding.
    InvalidValueLength(usize),
}

impl core::fmt::Display for BlockOptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockOptionError::InvalidBlockNumber(num) => {
                write!(f, "Invalid block number (expected <= 1048575, got {})", num)
            }
            BlockOptionError::InvalidBlockSize => write!(f, "Invalid block size exponent"),
            BlockOptionError::InvalidValueLength(len) => {
                write!(f, "Invalid block option length (expected 0-3, got {})", len)
            }
        }
    }
}

impl core::error::Error for BlockOptionError {}

impl From<BlockOptionError> for CoapBuildError {
    fn from(value: BlockOptionError) -> Self {
        CoapBuildError::InvalidBlockOption(value)
    }
}

impl From<BlockOptionError> for CoapParseError {
    fn from(err: BlockOptionError) -> Self {
        CoapParseError::InvalidBlockOption(err)
    }
}
