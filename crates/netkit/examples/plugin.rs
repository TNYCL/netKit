//! A length-prefixed custom protocol on an arbitrary TCP port.
use netkit::{
    Completeness, DecodeResult, Decoder, Engine, EngineConfig, Message, ProtocolRegistry,
    protocols::{DecodeContext, DecodeSession},
};
use std::sync::Arc;
struct Demo;
struct Session;
impl Decoder for Demo {
    fn name(&self) -> &str {
        "demo"
    }
    fn probe(&self, b: &[u8], _: DecodeContext) -> u8 {
        if b.starts_with(b"NK") { 100 } else { 0 }
    }
    fn session(&self) -> Box<dyn DecodeSession> {
        Box::new(Session)
    }
}
impl DecodeSession for Session {
    fn decode(&mut self, b: &[u8], ctx: DecodeContext, _: bool) -> DecodeResult {
        if b.len() < 4 {
            return DecodeResult::NeedMore;
        }
        if !b.starts_with(b"NK") {
            return DecodeResult::Invalid {
                consumed: b.len(),
                detail: "missing NK prefix".into(),
            };
        }
        let n = u16::from_be_bytes([b[2], b[3]]) as usize;
        if n + 4 > ctx.max_message {
            return DecodeResult::Invalid {
                consumed: 4,
                detail: "demo length limit".into(),
            };
        }
        if b.len() < n + 4 {
            return DecodeResult::NeedMore;
        }
        DecodeResult::Message {
            consumed: n + 4,
            message: Message {
                protocol: "demo".into(),
                completeness: Completeness::Complete,
                wire_len: n + 4,
                fields: serde_json::json!({"payload_length":n}),
            },
        }
    }
}
fn main() -> netkit::Result<()> {
    let mut registry = ProtocolRegistry::default();
    registry.register(Arc::new(Demo));
    let engine = Engine::with_registry(EngineConfig::default(), registry)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&engine.decode_message("demo", b"NK\0\x04TEST")?)?
    );
    Ok(())
}
