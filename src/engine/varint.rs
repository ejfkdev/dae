//! Dart `datastream.h` 的三种变长编码（跨版本稳定，引擎写死）。
//!
//! 字节语义与参考实现 `dart_aot_full.py` 完全一致：
//! - `ReadUnsigned`：LEB128 风格，终端字节 `kEndUnsignedByteMarker = 0x80`
//! - `Read<T>`（有符号）：终端字节 `kEndByteMarker = 0xC0`，终端贡献为 `b - 0xC0`（可为负）
//! - `ReadRefId`：大端 7-bit 分组，末字节 |0x80，读回 +128

#[derive(Debug)]
pub enum VarintError {
    UnexpectedEof,
}

pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

pub type R<T> = Result<T, VarintError>;

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    #[inline]
    fn byte(&mut self) -> R<u8> {
        let b = *self.data.get(self.pos).ok_or(VarintError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    /// ReadUnsigned：无符号 LEB128，终端 0x80。
    pub fn read_unsigned(&mut self) -> R<u64> {
        let mut r: u64 = 0;
        let mut s: u32 = 0;
        loop {
            let b = self.byte()?;
            r |= ((b & 0x7F) as u64) << s;
            if b & 0x80 != 0 {
                return Ok(r);
            }
            s += 7;
        }
    }

    /// Read<T>：有符号变长编码，终端 0xC0，终端位贡献 b - 0xC0。
    pub fn read_signed(&mut self) -> R<i64> {
        let mut r: i64 = 0;
        let mut s: u32 = 0;
        loop {
            let b = self.byte()?;
            if b & 0x80 != 0 {
                r |= ((b as i64) - 0xC0) << s;
                return Ok(r);
            }
            r |= ((b as i64) & 0x7F) << s;
            s += 7;
        }
    }

    /// ReadRefId：大端 7-bit 分组，终端 (b|0x80) 且返回值 +128。
    pub fn read_ref(&mut self) -> R<u64> {
        let mut r: i64 = 0;
        loop {
            let b = self.byte()?;
            let sb = if b & 0x80 != 0 { (b as i64) - 256 } else { b as i64 };
            r = sb + (r << 7);
            if sb < 0 {
                return Ok((r + 128) as u64);
            }
        }
    }

    /// ReadWordWith32BitReads：两个有符号变长（Read32 × 2，全版本一致）。
    pub fn read_word_32x2(&mut self) -> R<u64> {
        let lo = self.read_signed()?;
        let hi = self.read_signed()?;
        Ok(((hi as u64) << 32) | (lo as u64 & 0xFFFF_FFFF))
    }

    pub fn read_u8(&mut self) -> R<u8> {
        self.byte()
    }

    pub fn read_u32_le(&mut self) -> R<u32> {
        let b = self.data.get(self.pos..self.pos + 4).ok_or(VarintError::UnexpectedEof)?;
        self.pos += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64_le(&mut self) -> R<u64> {
        let b = self.data.get(self.pos..self.pos + 8).ok_or(VarintError::UnexpectedEof)?;
        self.pos += 8;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_i64_le(&mut self) -> R<i64> {
        Ok(self.read_u64_le()? as i64)
    }

    pub fn seek(&mut self, pos: usize) -> R<()> {
        if pos > self.data.len() {
            return Err(VarintError::UnexpectedEof);
        }
        self.pos = pos;
        Ok(())
    }

    pub fn skip(&mut self, n: usize) -> R<()> {
        if self.pos + n > self.data.len() {
            return Err(VarintError::UnexpectedEof);
        }
        self.pos += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_single_byte() {
        // 0x85 = 终端字节，值 5
        let mut r = Reader::new(&[0x85]);
        assert_eq!(r.read_unsigned().unwrap(), 5);
    }

    #[test]
    fn unsigned_two_byte() {
        // 300 = 0b10_0101100 → 低组 0x2C（非终端），高组 2|0x80 = 0x82
        let mut r = Reader::new(&[0x2C, 0x82]);
        assert_eq!(r.read_unsigned().unwrap(), 300);
    }

    #[test]
    fn signed_negative_single_byte() {
        // -1 = 单字节 0xBF（0xBF - 0xC0 = -1），必须为 -1 而非 63
        let mut r = Reader::new(&[0xBF]);
        assert_eq!(r.read_signed().unwrap(), -1);
    }

    #[test]
    fn signed_zero() {
        // 0 = 单字节 0xC0
        let mut r = Reader::new(&[0xC0]);
        assert_eq!(r.read_signed().unwrap(), 0);
    }

    #[test]
    fn signed_positive() {
        // 单字节 0xDF → 0xDF - 0xC0 = 31
        let mut r = Reader::new(&[0xDF]);
        assert_eq!(r.read_signed().unwrap(), 31);
    }

    #[test]
    fn signed_positive_two_bytes() {
        // 值 200：低 7 位 200&0x7F=72=0x48（非终端，高位置 0 → 0x48），
        // 高位组 200>>7=1，终端字节 0xC0+1=0xC1
        let mut r = Reader::new(&[0x48, 0xC1]);
        assert_eq!(r.read_signed().unwrap(), 200);
    }

    #[test]
    fn ref_id_zero() {
        // ref 0 编码 = 终端字节 0x80 → (0x80-256) + 128 = 0
        let mut r = Reader::new(&[0x80]);
        assert_eq!(r.read_ref().unwrap(), 0);
    }

    #[test]
    fn ref_id_plain_group() {
        // ref 5: 0x80|5 = 0x85 → (0x85-256)+128 = 5
        let mut r = Reader::new(&[0x85]);
        assert_eq!(r.read_ref().unwrap(), 5);
    }

    #[test]
    fn word_32x2() {
        // -1 编码 0xBF（lo），hi=2 → 0xC2。结果 (2<<32) | 0xFFFFFFFF
        let mut r = Reader::new(&[0xBF, 0xC2]);
        assert_eq!(r.read_word_32x2().unwrap(), 0x2_FFFF_FFFF);
    }
}