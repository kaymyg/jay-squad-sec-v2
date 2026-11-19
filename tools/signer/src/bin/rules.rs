//! jaysec-rules — author detection-rule payloads for signed updates.
//!
//! Rules are edited as plain `key = value` text, compiled into the validated
//! binary payload that `jaysec-sign` signs, and can be inspected again later.
//!
//!   jaysec-rules export-defaults rules.txt     # complete template, current values
//!   jaysec-rules compile rules.txt rules.bin   # parse + validate + encode
//!   jaysec-rules show rules.bin                # or a signed .jssp patch
//!
//! Compilation is strict on purpose: every key must appear exactly once, no
//! unknown keys, and the result must pass the same validation the product
//! enforces. An omitted key never silently falls back to a default.

use jay_squad_sec::rules::{RulesConfig, DEFAULT_RULES, KINDS, RULES_MAGIC};
use jay_squad_sec_protocol::{kind_from_wire, wire_from_kind};
use jay_squad_sec_update::{SignedPatch, PATCH_MAGIC};
use std::collections::BTreeSet;
use std::io::Write;
use std::process::exit;

const SCALARS: [&str; 5] = ["half_life_ms", "monitor_at", "restrict_at", "suspend_at", "block_at"];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["export-defaults", out] => export_defaults(out),
        ["compile", input, out] => compile(input, out),
        ["show", file] => show(file),
        ["--help"] | ["-h"] | [] => {
            usage();
            Ok(())
        }
        _ => {
            usage();
            exit(2);
        }
    };
    if let Err(msg) = result {
        eprintln!("error: {msg}");
        exit(1);
    }
}

fn usage() {
    eprintln!("jaysec-rules export-defaults OUT.txt");
    eprintln!("jaysec-rules compile IN.txt OUT.bin");
    eprintln!("jaysec-rules show FILE   (rules .bin or signed .jssp)");
}

/// Render a config as the editable text format. f32 Display prints the
/// shortest string that round-trips, so export -> compile is exact.
fn to_text(r: &RulesConfig) -> String {
    let mut s = String::new();
    s.push_str("# Jay Squad Sec detection rules.\n");
    s.push_str("# Every key is required. Validation (enforced again on-device):\n");
    s.push_str("#  - threat indicators: weight in [1, 100] (no detection can be silenced)\n");
    s.push_str("#  - neutral events (process_start/exit, network_connect, file_write): [0, 5]\n");
    s.push_str("#  - good evidence (signed_binary, stable_tick): [-20, 0]\n");
    s.push_str("#  - half_life_ms in [10000, 3600000]\n");
    s.push_str("#  - 5 <= monitor_at < restrict_at < suspend_at < block_at <= 400, steps >= 5\n");
    s.push_str("#  - the 5 strongest indicator weights must sum to at least block_at\n\n");
    s.push_str(&format!("half_life_ms = {}\n", r.half_life_ms));
    s.push_str(&format!("monitor_at = {}\n", r.monitor_at));
    s.push_str(&format!("restrict_at = {}\n", r.restrict_at));
    s.push_str(&format!("suspend_at = {}\n", r.suspend_at));
    s.push_str(&format!("block_at = {}\n\n", r.block_at));
    for k in KINDS {
        s.push_str(&format!("weight.{} = {}\n", wire_from_kind(k), r.weight(k)));
    }
    s
}

fn parse_text(text: &str) -> Result<RulesConfig, String> {
    let mut cfg = DEFAULT_RULES; // every field is overwritten; presence is enforced below
    let mut seen = BTreeSet::new();
    for (lineno, raw) in text.lines().enumerate() {
        let n = lineno + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("line {n}: expected `key = value`"))?;
        let (key, val) = (key.trim(), val.trim());
        let v: f32 = val.parse().map_err(|_| format!("line {n}: `{val}` is not a number"))?;
        if !seen.insert(key.to_string()) {
            return Err(format!("line {n}: duplicate key `{key}`"));
        }
        match key {
            "half_life_ms" => cfg.half_life_ms = v,
            "monitor_at" => cfg.monitor_at = v,
            "restrict_at" => cfg.restrict_at = v,
            "suspend_at" => cfg.suspend_at = v,
            "block_at" => cfg.block_at = v,
            other => {
                let kind = other
                    .strip_prefix("weight.")
                    .and_then(kind_from_wire)
                    .ok_or_else(|| format!("line {n}: unknown key `{other}`"))?;
                cfg.weights[jay_squad_sec::rules::kind_index(kind)] = v;
            }
        }
    }
    let mut missing: Vec<String> = SCALARS.iter().map(|s| s.to_string()).collect();
    missing.extend(KINDS.iter().map(|k| format!("weight.{}", wire_from_kind(*k))));
    missing.retain(|k| !seen.contains(k));
    if !missing.is_empty() {
        return Err(format!("missing keys: {}", missing.join(", ")));
    }
    cfg.validate().map_err(|e| format!("invalid rules: {e}"))?;
    Ok(cfg)
}

fn export_defaults(out: &str) -> Result<(), String> {
    // Refuse to overwrite: this file is usually being hand-edited.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| format!("cannot create {out}: {e} (refusing to overwrite)"))?;
    f.write_all(to_text(&DEFAULT_RULES).as_bytes()).map_err(|e| e.to_string())?;
    println!("Default rules template written: {out}");
    Ok(())
}

fn compile(input: &str, out: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(input).map_err(|e| format!("cannot read {input}: {e}"))?;
    let cfg = parse_text(&text)?;
    std::fs::write(out, cfg.encode()).map_err(|e| format!("cannot write {out}: {e}"))?;
    println!("Validated rules payload written: {out} ({} bytes)", cfg.encode().len());
    println!("Next: jaysec-sign --key KEY --product ID --version N --payload {out} --out PATCH.jssp");
    Ok(())
}

fn show(file: &str) -> Result<(), String> {
    let bytes = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    let cfg = if bytes.starts_with(PATCH_MAGIC) {
        let p = SignedPatch::decode(&bytes).map_err(|e| e.to_string())?;
        println!("# signed patch: product={} version={}", p.manifest.product_id, p.manifest.patch_version);
        println!("# NOTE: signature NOT checked here; use jaysec-verify for that.\n");
        RulesConfig::decode(&p.payload).map_err(|e| format!("payload is not valid rules: {e}"))?
    } else if bytes.starts_with(RULES_MAGIC) {
        RulesConfig::decode(&bytes).map_err(|e| format!("invalid rules: {e}"))?
    } else {
        return Err("not a rules payload or signed patch".into());
    };
    print!("{}", to_text(&cfg));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_then_parse_round_trips_exactly() {
        assert_eq!(parse_text(&to_text(&DEFAULT_RULES)), Ok(DEFAULT_RULES));
    }

    #[test]
    fn missing_unknown_and_duplicate_keys_are_rejected() {
        let full = to_text(&DEFAULT_RULES);
        let without_block: String =
            full.lines().filter(|l| !l.starts_with("block_at")).collect::<Vec<_>>().join("\n");
        assert!(parse_text(&without_block).unwrap_err().contains("missing keys: block_at"));
        assert!(parse_text(&format!("{full}\nweight.not_a_kind = 1\n"))
            .unwrap_err()
            .contains("unknown key"));
        assert!(parse_text(&format!("{full}\nblock_at = 120\n"))
            .unwrap_err()
            .contains("duplicate key"));
    }

    #[test]
    fn invalid_values_are_rejected_with_the_product_rule() {
        let edited = to_text(&DEFAULT_RULES).replace("weight.credential_access = 40", "weight.credential_access = 0");
        assert!(parse_text(&edited).unwrap_err().contains("cannot be silenced"));
        let nan = to_text(&DEFAULT_RULES).replace("block_at = 100", "block_at = NaN");
        assert!(parse_text(&nan).is_err());
    }
}
