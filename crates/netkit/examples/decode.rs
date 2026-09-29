use netkit::{Engine, EngineConfig};
fn main() -> netkit::Result<()> {
    let engine = Engine::new(EngineConfig::default())?;
    let bytes=b"\x0bMSH|^~\\&|DEMO|LAB|NETKIT|TEST|20260929||ORU^R01|SYNTHETIC-1|P|2.5\rPID|1||SYNTHETIC\r\x1c\r";
    for message in engine.decode_message("hl7", bytes)? {
        println!("{}", serde_json::to_string_pretty(&message)?);
    }
    Ok(())
}
