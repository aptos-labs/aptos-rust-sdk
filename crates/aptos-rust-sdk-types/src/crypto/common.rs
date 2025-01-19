pub fn to_hex_string<T: AsRef<[u8]>>(bytes: T) -> String {
    format!("0x{}", hex::encode(bytes))
}
