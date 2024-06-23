use sha3::{Digest, Keccak256};
extern crate ebnf;
use ethers::prelude::*;
use ethers::utils::{hex, hexlify, keccak256};
use std::error::Error;
use std::str::FromStr;
use tokio::sync::OnceCell;
use ebnf::{Node, SymbolKind, RegexExtKind};

#[derive(Debug, Clone)]
pub struct DmapLib {
    pub address: String,
    pub artifact: String,
    pub flag_lock: u8,
    pub grammar: ebnf::Grammar,
    pub parser: OnceCell<Parse
}

impl DmapLib {
    pub fn new(address: String, artifact: String) -> Self {

        let gram = r#"
            dpath ::= (step)* EOF
            step  ::= (rune) (name)
            name  ::= [a-z]+
            rune  ::= ":" | "."
        "#;
        let grammar = ebnf::get_grammar(&gram).unwrap();

    

        Self {
            address,
            artifact,
            flag_lock: 1,
            grammar,
            parser: OnceCell::new(),
        }
    }

    pub fn init_parser(&self) {
        let rules = grammar::Grammars::W3C.get_rules(self.grammar).expect("Invalid grammar");
        self.parser.get_or_init(|| grammar::Parser::new(rules));
    }

    pub fn parse(&self, input: &str) -> Result<Vec<Step>, Box<dyn Error>> {
        self.init_parser();
        let ast = self.parser.get().unwrap().parse(input).map_err(|e| e.to_string())?;
        let mut steps = Vec::new();
        for step in ast.children {
            let rune = step.children[0].text;
            let name = step.children[1].text;
            steps.push(Step {
                locked: rune == ":",
                name: name.to_string(),
            });
        }
        Ok(steps)
    }

    pub async fn get(&self, dmap: &Dmap, slot: &str) -> Result<(String, String), Box<dyn Error>> {
        let nextslot = hex_zero_pad(hexlify(slot.parse::<u128>()? + 1)?, 32);
        let (meta, data) = tokio::try_join!(
            dmap.provider.get_storage_at(&dmap.address, slot),
            dmap.provider.get_storage_at(&dmap.address, &nextslot)
        )?;
        Ok((meta, data))
    }

    pub async fn get_by_zone_and_name(&self, dmap: &Dmap, zone: &str, name: &str) -> Result<(String, String), Box<dyn Error>> {
        let slot = keccak256(&encode_zone_and_name(zone, name));
        self.get(dmap, &slot).await
    }

    pub async fn set(&self, dmap: &Dmap, name: &str, meta: &str, data: &str) -> Result<(), Box<dyn Error>> {
        let calldata = encode_function_call_bytes32_args("set(bytes32,bytes32,bytes32)", &[name, meta, data]);
        dmap.signer.send_transaction(TransactionRequest {
            to: Some(dmap.address.parse()?),
            data: Some(calldata.into()),
            ..Default::default()
        }).await?;
        Ok(())
    }

    pub async fn walk(&self, dmap: &Dmap, path: &str) -> Result<(String, String), Box<dyn Error>> {
        let mut path = path.to_string();
        if !path.is_empty() && ![":", "."].contains(&path.chars().next().unwrap().to_string().as_str()) {
            path = format!(":{}", path);
        }

        let (mut meta, mut data) = self.get(dmap, "0x0000000000000000000000000000000000000000000000000000000000000000").await?;
        let mut ctx = Context { locked: path.chars().next().unwrap() == ':' };

        for step in self.parse(&path)? {
            let zone = &data[0..42];
            if zone == "0x0000000000000000000000000000000000000000" {
                return Err("zero register".into());
            }
            let fullname = format!("0x{}{}", str_to_hex(&step.name), "00".repeat(32 - step.name.len()));
            (meta, data) = self.get_by_zone_and_name(dmap, zone, &fullname).await?;
            if step.locked {
                if !ctx.locked {
                    return Err("Encountered ':' in unlocked subpath".into());
                }
                if hex_to_array_buffer(&meta)[31] & self.flag_lock == 0 {
                    return Err("Entry is not locked".into());
                }
                ctx.locked = true;
            }
            ctx.locked = step.locked;
        }

        Ok((meta, data))
    }
}

#[derive(Debug, Clone)]
pub struct Dmap {
    pub address: String,
    pub provider: Provider<Http>,
    pub signer: Wallet<Provider<Http>>,
}

#[derive(Debug)]
pub struct Step {
    pub locked: bool,
    pub name: String,
}

#[derive(Debug)]
pub struct Context {
    pub locked: bool,
}

pub fn hex_zero_pad(value: String, length: usize) -> String {
    let mut value = value;
    if value.len() > 2 * length + 2 {
        panic!("Value too big");
    }
    while value.len() < 2 * length + 2 {
        value.insert_str(2, "0");
    }
    value
}

pub fn str_to_hex(s: &str) -> String {
    s.chars().map(|c| format!("{:02x}", c as u8)).collect()
}

pub fn hex_to_array_buffer(hex: &str) -> Vec<u8> {
    hex::decode(&hex[2..]).unwrap()
}

pub fn encode_zone_and_name(zone: &str, name: &str) -> String {
    let mut params = format!("0x{}", "00".repeat(12));
    if zone.is_empty() {
        params.push_str(&"00".repeat(20));
    } else {
        params.push_str(&zone[2..]);
    }
    if name.is_empty() {
        params.push_str(&"00".repeat(32));
    } else {
        params.push_str(&name[2..]);
    }
    params
}

pub fn encode_function_call_bytes32_args(signature: &str, args: &[&str]) -> String {
    let mut data = keccak256(signature).to_string()[0..10].to_string();
    for arg in args {
        if arg.starts_with("0x") {
            data.push_str(&arg[2..]);
        } else {
            data.push_str(arg);
        }
    }
    data
}