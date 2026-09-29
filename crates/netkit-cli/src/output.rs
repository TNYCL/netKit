use crate::Format;
use netkit::Result;
use serde_json::Value;
use std::io::{self, BufWriter, Write};

pub struct Output {
    writer: BufWriter<io::Stdout>,
    format: Format,
    first: bool,
}
impl Output {
    pub fn new(format: Format) -> Result<Self> {
        let mut this = Self {
            writer: BufWriter::new(io::stdout()),
            format,
            first: true,
        };
        if format == Format::Json {
            write!(this.writer, "[")?;
        }
        Ok(this)
    }
    pub fn emit<T: serde::Serialize>(&mut self, value: &T) -> Result<()> {
        let value = serde_json::to_value(value)?;
        match self.format {
            Format::Json => {
                if !self.first {
                    write!(self.writer, ",")?;
                }
                serde_json::to_writer(&mut self.writer, &value)?;
            }
            Format::Jsonl => {
                serde_json::to_writer(&mut self.writer, &value)?;
                writeln!(self.writer)?;
            }
            Format::Table => writeln!(self.writer, "{}", human(&value))?,
        }
        self.first = false;
        self.writer.flush()?;
        Ok(())
    }
    pub fn finish(&mut self) -> Result<()> {
        if self.format == Format::Json {
            writeln!(self.writer, "]")?;
        }
        self.writer.flush()?;
        Ok(())
    }
}
fn human(v: &Value) -> String {
    let s = |key: &str| v[key].as_str().unwrap_or("-");
    match s("type") {
        "message_decoded" => format!(
            "MESSAGE  flow={}  {:<8} {:<10} {} bytes",
            v["flow_id"],
            v["message"]["protocol"].as_str().unwrap_or("?"),
            v["message"]["completeness"].as_str().unwrap_or("?"),
            v["message"]["wire_len"]
        ),
        "device_observed" => format!(
            "DEVICE   {:<39} {:<17} {}",
            v["device"]["ip"].as_str().unwrap_or("?"),
            v["device"]["mac"].as_str().unwrap_or("-"),
            v["device"]["names"]
        ),
        "flow_opened" | "flow_closed" => format!(
            "{:<12} #{}  {}:{} <-> {}:{}  {}  {}",
            s("type"),
            v["flow"]["id"],
            v["flow"]["key"]["a"]["ip"].as_str().unwrap_or("?"),
            v["flow"]["key"]["a"]["port"],
            v["flow"]["key"]["b"]["ip"].as_str().unwrap_or("?"),
            v["flow"]["key"]["b"]["port"],
            v["flow"]["key"]["transport"].as_str().unwrap_or("other"),
            v["flow"]["protocols"]
        ),
        "diagnostic" => format!("DIAGNOSTIC {:<24} {}", s("code"), s("detail")),
        "statistics" => format!("STATISTICS {}", v["counters"]),
        "packet_observed" => format!(
            "PACKET   #{} interface={} {} bytes {}",
            v["packet_id"], v["source"]["interface"], v["captured_len"], v["layers"]
        ),
        _ if v.get("monitor_mode").is_some() => format!(
            "{:<3} {:<48} monitor={:<5} {}",
            v["id"],
            s("name"),
            v["monitor_mode"],
            s("description")
        ),
        _ if v.get("state").is_some() => format!(
            "{:<39} {:>5} {:<5} {:<20} {}",
            s("address"),
            v["port"],
            s("transport"),
            s("state"),
            s("evidence")
        ),
        _ if v.get("native").is_some() => format!(
            "{:<24} {}{}{}",
            s("name"),
            s("native"),
            v.get("external")
                .map(|e| format!("; external: {e}"))
                .unwrap_or_default(),
            v.get("limitations")
                .map(|e| format!("; limits: {e}"))
                .unwrap_or_default()
        ),
        _ => serde_json::to_string_pretty(v).unwrap_or_default(),
    }
}
