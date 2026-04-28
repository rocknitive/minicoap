use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{BlockOptionError, CoapOption};

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
/// Valid block sizes for CoAP block-wise transfer options.
pub enum BlockSize {
    /// 16-byte blocks.
    B16 = 0,
    /// 32-byte blocks.
    B32 = 1,
    /// 64-byte blocks.
    B64 = 2,
    /// 128-byte blocks.
    B128 = 3,
    /// 256-byte blocks.
    B256 = 4,
    /// 512-byte blocks.
    B512 = 5,
    /// 1024-byte blocks.
    B1024 = 6,
}

impl BlockSize {
    /// Returns the block size in bytes.
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::B16 => 16,
            Self::B32 => 32,
            Self::B64 => 64,
            Self::B128 => 128,
            Self::B256 => 256,
            Self::B512 => 512,
            Self::B1024 => 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// Decoded value of the `Block1` or `Block2` option.
pub struct BlockOption {
    /// Block number.
    pub num: u32,
    /// Whether more blocks follow.
    pub more: bool,
    /// Size of each block.
    pub size: BlockSize,
}

impl BlockOption {
    /// Maximum block number encodable in a 3-byte block option value.
    pub const MAX_NUM: u32 = 0x000F_FFFF;

    /// Creates a block option value.
    pub const fn new(num: u32, more: bool, size: BlockSize) -> Result<Self, BlockOptionError> {
        if num > Self::MAX_NUM {
            return Err(BlockOptionError::InvalidBlockNumber(num as u64));
        }

        Ok(Self { num, more, size })
    }

    /// Returns the block size in bytes.
    pub const fn size_bytes(self) -> usize {
        self.size.size_bytes()
    }

    /// Returns the byte offset covered by this block number.
    pub const fn offset(self) -> usize {
        self.num as usize * self.size.size_bytes()
    }

    /// Decodes a block option directly from the raw option bytes.
    pub fn try_from_option(option: &CoapOption) -> Result<Self, BlockOptionError> {
        // The value of the Block option is a variable-size (0 to 3 byte) unsigned integer
        // Source: [RFC 7959 2.2](https://datatracker.ietf.org/doc/html/rfc7959#section-2.2)
        if option.value.len() > 3 {
            return Err(BlockOptionError::InvalidValueLength(option.value.len()));
        }

        let value = option
            .as_uint()
            .ok_or(BlockOptionError::InvalidValueLength(option.value.len()))?;
        Self::try_from_uint(value)
    }

    /// Decodes a packed CoAP block option integer.
    pub fn try_from_uint(value: u64) -> Result<Self, BlockOptionError> {
        let szx = (value & 0x07) as u8;
        let size = BlockSize::try_from(szx).map_err(|_| BlockOptionError::InvalidBlockSize)?;
        let more = (value & 0x08) != 0;
        let num = (value >> 4)
            .try_into()
            .map_err(|_| BlockOptionError::InvalidBlockNumber(value >> 4))?;

        Self::new(num, more, size)
    }
}

impl From<BlockOption> for u64 {
    fn from(value: BlockOption) -> Self {
        ((value.num as u64) << 4) | ((value.more as u64) << 3) | u8::from(value.size) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OptionNumber;

    #[test]
    fn block_option_roundtrip_uint() {
        let block = BlockOption::new(0x12345, true, BlockSize::B512).unwrap();
        let encoded = u64::from(block);

        assert_eq!(BlockOption::try_from_uint(encoded), Ok(block));
    }

    #[test]
    fn block_option_try_from_option_zero_length() {
        let option = CoapOption {
            number: OptionNumber::Block2,
            value: &[],
        };

        assert_eq!(
            BlockOption::try_from_option(&option),
            Ok(BlockOption::new(0, false, BlockSize::B16).unwrap())
        );
    }

    #[test]
    fn block_option_try_from_option_three_bytes() {
        let encoded = [0x12, 0x3d, 0x5e];
        let option = CoapOption {
            number: OptionNumber::Block1,
            value: &encoded,
        };

        assert_eq!(
            BlockOption::try_from_option(&option),
            Ok(BlockOption::new(0x123d5, true, BlockSize::B1024).unwrap())
        );
    }

    #[test]
    fn block_option_rejects_invalid_szx() {
        assert_eq!(
            BlockOption::try_from_uint(0x07),
            Err(BlockOptionError::InvalidBlockSize)
        );
    }

    #[test]
    fn block_option_rejects_too_many_bytes() {
        let encoded = [0x00, 0x00, 0x00, 0x00];
        let option = CoapOption {
            number: OptionNumber::Block2,
            value: &encoded,
        };

        assert_eq!(
            BlockOption::try_from_option(&option),
            Err(BlockOptionError::InvalidValueLength(4))
        );
    }

    #[test]
    fn block_option_offset_and_size() {
        let block = BlockOption::new(3, false, BlockSize::B128).unwrap();

        assert_eq!(block.size.size_bytes(), 128);
        assert_eq!(block.offset(), 384);
    }

    #[test]
    fn block_option_accepts_max_num() {
        let block = BlockOption::new(BlockOption::MAX_NUM, false, BlockSize::B16).unwrap();

        assert_eq!(block.num, BlockOption::MAX_NUM);
    }

    #[test]
    fn block_option_rejects_num_above_max() {
        assert_eq!(
            BlockOption::new(BlockOption::MAX_NUM + 1, false, BlockSize::B16),
            Err(BlockOptionError::InvalidBlockNumber(
                (BlockOption::MAX_NUM + 1) as u64
            ))
        );
    }
}
