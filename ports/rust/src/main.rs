//! Rust port of the modpot CORE check: decode a Modbus/TCP frame (hex) and
//! classify it into a severity. No external crates.
//!
//! Usage:
//!   echo 000100000006010600010001 | modpot
//!   modpot 000100000006010300000001

use std::io::Read;

#[derive(Debug, PartialEq)]
pub struct Event {
    pub function_code: u8,
    pub function_name: String,
    pub category: String,
    pub severity: String,
    pub address: i32,
    pub quantity: i32,
    pub reasons: Vec<String>,
}

fn function_name(fc: u8) -> String {
    let n = match fc {
        0x01 => "read_coils",
        0x02 => "read_discrete_inputs",
        0x03 => "read_holding_registers",
        0x04 => "read_input_registers",
        0x05 => "write_single_coil",
        0x06 => "write_single_register",
        0x0F => "write_multiple_coils",
        0x10 => "write_multiple_registers",
        0x16 => "mask_write_register",
        0x17 => "read_write_multiple_registers",
        0x2B => "encapsulated_interface_transport",
        0x08 => "diagnostics",
        0x11 => "report_server_id",
        _ => return format!("unknown_0x{:02x}", fc),
    };
    n.to_string()
}

const READ_CODES: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
const WRITE_CODES: [u8; 5] = [0x05, 0x06, 0x0F, 0x10, 0x16];
const SUSPICIOUS_CODES: [u8; 4] = [0x08, 0x11, 0x2B, 0x16];

pub fn parse_and_classify(buf: &[u8]) -> Result<Event, String> {
    if buf.len() < 8 {
        return Err("frame too short".into());
    }
    let pid = ((buf[2] as u16) << 8) | buf[3] as u16;
    if pid != 0 {
        return Err(format!("bad protocol id 0x{:04x}", pid));
    }
    let length = ((buf[4] as u16) << 8) | buf[5] as u16;
    if length < 2 {
        return Err(format!("bad MBAP length {}", length));
    }
    let fc = buf[7];
    let body = &buf[8..];
    let mut address: i32 = -1;
    let mut quantity: i32 = -1;
    if READ_CODES.contains(&fc) && body.len() >= 4 {
        address = ((body[0] as i32) << 8) | body[1] as i32;
        quantity = ((body[2] as i32) << 8) | body[3] as i32;
    } else if (fc == 0x05 || fc == 0x06) && body.len() >= 4 {
        address = ((body[0] as i32) << 8) | body[1] as i32;
    }

    let known = function_name(fc);
    let category = if WRITE_CODES.contains(&fc) {
        "write"
    } else if READ_CODES.contains(&fc) {
        "read"
    } else if !known.starts_with("unknown_") {
        "control"
    } else {
        "unknown"
    };

    let mut severity = "info".to_string();
    let mut reasons: Vec<String> = Vec::new();
    if category == "read" {
        severity = "low".into();
        if quantity > 125 {
            severity = "medium".into();
            reasons.push(format!("oversized read quantity {} (>125)", quantity));
        }
    }
    if category == "write" {
        severity = "high".into();
        reasons.push("register/coil write attempt against control device".into());
    }
    if SUSPICIOUS_CODES.contains(&fc) {
        severity = "high".into();
        reasons.push(format!("suspicious function {} (recon/tamper)", known));
    }
    if category == "unknown" {
        severity = "medium".into();
        reasons.push("unknown function code (scanner/fuzzing)".into());
    }
    if reasons.is_empty() {
        reasons.push("benign register read".into());
    }

    Ok(Event {
        function_code: fc,
        function_name: known,
        category: category.into(),
        severity,
        address,
        quantity,
        reasons,
    })
}

fn clean_hex(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_hexdigit()).collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = clean_hex(s);
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() {
    let arg = std::env::args().nth(1);
    let input = match arg {
        Some(a) => a,
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).ok();
            s.lines().next().unwrap_or("").to_string()
        }
    };
    let raw = match decode_hex(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bad hex: {}", e);
            std::process::exit(2);
        }
    };
    match parse_and_classify(&raw) {
        Ok(e) => {
            let reasons = e
                .reasons
                .iter()
                .map(|r| format!("{:?}", r))
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{{\"tool\":\"modpot\",\"event\":{{\"function_name\":{:?},\"category\":{:?},\"severity\":{:?},\"address\":{},\"quantity\":{},\"reasons\":[{}]}}}}",
                e.function_name, e.category, e.severity, e.address, e.quantity, reasons
            );
            if e.severity == "high" {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("parse error: {}", e);
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Vec<u8> {
        decode_hex(s).unwrap()
    }

    #[test]
    fn read_holding_is_low() {
        let e = parse_and_classify(&d("000100000006010300000001")).unwrap();
        assert_eq!(e.function_name, "read_holding_registers");
        assert_eq!(e.severity, "low");
    }

    #[test]
    fn write_single_is_high() {
        let e = parse_and_classify(&d("000200000006010600010001")).unwrap();
        assert_eq!(e.category, "write");
        assert_eq!(e.severity, "high");
    }

    #[test]
    fn oversized_read_is_medium() {
        let e = parse_and_classify(&d("0001000000060103000000C9")).unwrap();
        assert_eq!(e.severity, "medium");
    }

    #[test]
    fn report_server_id_is_high() {
        let e = parse_and_classify(&d("0009000000020111")).unwrap();
        assert_eq!(e.severity, "high");
    }

    #[test]
    fn bad_protocol_id_errors() {
        assert!(parse_and_classify(&d("0001DEAD0006010300000001")).is_err());
    }

    #[test]
    fn short_frame_errors() {
        assert!(parse_and_classify(&[0, 1, 0]).is_err());
    }

    #[test]
    fn unknown_function_is_medium() {
        let e = parse_and_classify(&d("0001000000020163")).unwrap();
        assert_eq!(e.category, "unknown");
        assert_eq!(e.severity, "medium");
    }

    #[test]
    fn clean_hex_strips() {
        assert_eq!(clean_hex("00 01 ab"), "0001ab");
    }
}
