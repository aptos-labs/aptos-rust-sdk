use crate::api_types::address::AccountAddress;
use crate::api_types::type_tag::{StructTag, TypeTag};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, hex_digit1},
    combinator::{all_consuming, map, map_res, opt},
    multi::separated_list0,
    sequence::{delimited, preceded},
    IResult, Parser,
};
use std::str::FromStr;

/// Parse a type tag from a string representation
pub fn parse_type_tag(input: &str) -> Result<TypeTag, anyhow::Error> {
    match all_consuming(type_tag).parse(input) {
        Ok((_, tag)) => Ok(tag),
        Err(e) => Err(anyhow::anyhow!("Failed to parse type tag: {}", e)),
    }
}

/// Parse a struct tag from a string representation
pub fn parse_struct_tag(input: &str) -> Result<StructTag, anyhow::Error> {
    match all_consuming(struct_tag).parse(input) {
        Ok((_, tag)) => Ok(tag),
        Err(e) => Err(anyhow::anyhow!("Failed to parse struct tag: {}", e)),
    }
}

fn type_tag(input: &str) -> IResult<&str, TypeTag> {
    alt((
        primitive_type,
        vector_type,
        map(struct_tag, |s| TypeTag::Struct(Box::new(s))),
    ))
    .parse(input)
}

fn primitive_type(input: &str) -> IResult<&str, TypeTag> {
    alt((
        map(tag("bool"), |_| TypeTag::Bool),
        map(tag("u8"), |_| TypeTag::U8),
        map(tag("u16"), |_| TypeTag::U16),
        map(tag("u32"), |_| TypeTag::U32),
        map(tag("u64"), |_| TypeTag::U64),
        map(tag("u128"), |_| TypeTag::U128),
        map(tag("u256"), |_| TypeTag::U256),
        map(tag("address"), |_| TypeTag::Address),
        map(tag("signer"), |_| TypeTag::Signer),
    ))
    .parse(input)
}

fn vector_type(input: &str) -> IResult<&str, TypeTag> {
    map(
        preceded(tag("vector"), delimited(char('<'), type_tag, char('>'))),
        |inner| TypeTag::Vector(Box::new(inner)),
    )
    .parse(input)
}

fn struct_tag(input: &str) -> IResult<&str, StructTag> {
    map(
        (
            account_address,
            preceded(tag("::"), identifier),
            preceded(tag("::"), identifier),
            opt(delimited(
                delimited(
                    nom::character::complete::multispace0,
                    char('<'),
                    nom::character::complete::multispace0,
                ),
                separated_list0(
                    delimited(
                        nom::character::complete::multispace0,
                        char(','),
                        nom::character::complete::multispace0,
                    ),
                    type_tag,
                ),
                delimited(
                    nom::character::complete::multispace0,
                    char('>'),
                    nom::character::complete::multispace0,
                ),
            )),
        ),
        |(address, module, name, type_args)| StructTag {
            address,
            module,
            name,
            type_args: type_args.unwrap_or_default(),
        },
    )
    .parse(input)
}

fn account_address(input: &str) -> IResult<&str, AccountAddress> {
    map_res(preceded(tag("0x"), hex_digit1), |hex_str: &str| {
        AccountAddress::from_str(&format!("0x{}", hex_str))
    })
    .parse(input)
}

fn identifier(input: &str) -> IResult<&str, String> {
    map(
        take_while1(|c: char| c.is_alphanumeric() || c == '_'),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primitive_types() {
        assert_eq!(parse_type_tag("bool").unwrap(), TypeTag::Bool);
        assert_eq!(parse_type_tag("u8").unwrap(), TypeTag::U8);
        assert_eq!(parse_type_tag("u16").unwrap(), TypeTag::U16);
        assert_eq!(parse_type_tag("u32").unwrap(), TypeTag::U32);
        assert_eq!(parse_type_tag("u64").unwrap(), TypeTag::U64);
        assert_eq!(parse_type_tag("u128").unwrap(), TypeTag::U128);
        assert_eq!(parse_type_tag("u256").unwrap(), TypeTag::U256);
        assert_eq!(parse_type_tag("address").unwrap(), TypeTag::Address);
        assert_eq!(parse_type_tag("signer").unwrap(), TypeTag::Signer);
    }

    #[test]
    fn test_parse_vector_type() {
        let result = parse_type_tag("vector<u8>").unwrap();
        assert_eq!(result, TypeTag::Vector(Box::new(TypeTag::U8)));

        let result = parse_type_tag("vector<vector<u64>>").unwrap();
        assert_eq!(
            result,
            TypeTag::Vector(Box::new(TypeTag::Vector(Box::new(TypeTag::U64))))
        );
    }

    #[test]
    fn test_parse_struct_tag() {
        let result = parse_struct_tag("0x1::string::String").unwrap();
        assert_eq!(result.address, AccountAddress::from_str("0x1").unwrap());
        assert_eq!(result.module, "string");
        assert_eq!(result.name, "String");
        assert_eq!(result.type_args, vec![]);
    }

    #[test]
    fn test_parse_struct_tag_with_generics() {
        let result = parse_struct_tag("0x1::option::Option<u64>").unwrap();
        assert_eq!(result.address, AccountAddress::from_str("0x1").unwrap());
        assert_eq!(result.module, "option");
        assert_eq!(result.name, "Option");
        assert_eq!(result.type_args, vec![TypeTag::U64]);
    }

    #[test]
    fn test_parse_complex_struct_tag() {
        let result = parse_struct_tag("0x1::coin::Coin<0x1::aptos_coin::AptosCoin>").unwrap();
        assert_eq!(result.address, AccountAddress::from_str("0x1").unwrap());
        assert_eq!(result.module, "coin");
        assert_eq!(result.name, "Coin");
        assert_eq!(result.type_args.len(), 1);

        if let TypeTag::Struct(inner) = &result.type_args[0] {
            assert_eq!(inner.address, AccountAddress::from_str("0x1").unwrap());
            assert_eq!(inner.module, "aptos_coin");
            assert_eq!(inner.name, "AptosCoin");
        } else {
            panic!("Expected struct type parameter");
        }
    }

    #[test]
    fn test_roundtrip_type_tag() {
        let test_cases = vec!["bool", "u8", "u64", "vector<u8>", "vector<vector<u64>>"];

        for case in test_cases {
            let parsed = parse_type_tag(case).unwrap();
            assert_eq!(parsed.to_canonical_string(), case);
        }
    }

    #[test]
    fn test_roundtrip_struct_tag() {
        let test_cases = vec![
            "0x1::string::String",
            "0x1::option::Option<u64>",
            "0x1::coin::Coin<0x1::aptos_coin::AptosCoin>",
        ];

        for case in test_cases {
            let parsed = parse_struct_tag(case).unwrap();
            assert_eq!(parsed.to_canonical_string(), case);
        }
    }
}
