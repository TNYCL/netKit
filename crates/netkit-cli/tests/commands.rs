use std::process::Command;
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_netkit"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn help_has_all_public_commands() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for command in [
        "interfaces",
        "capture",
        "devices",
        "flows",
        "analyze",
        "decode",
        "discover",
        "scan",
        "protocols",
        "doctor",
        "config",
        "deep",
        "benchmark",
    ] {
        assert!(text.contains(command), "{command}");
    }
}
#[test]
fn protocols_and_doctor_produce_machine_readable_json_without_drivers() {
    for cmd in ["protocols", "doctor"] {
        let out = run(&[cmd, "--format", "json"]);
        assert!(out.status.success(), "{:?}", out);
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(value.is_array());
        assert!(!value.as_array().unwrap().is_empty());
    }
}
#[test]
fn invalid_target_fails_without_scanning() {
    let out = run(&["scan", "--target", "not-an-address", "--format", "json"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
        serde_json::json!([])
    );
}
#[test]
fn config_template_is_valid_and_redacts_by_default() {
    let out = run(&["config"]);
    assert!(out.status.success());
    let config: toml::Value = toml::from_str(std::str::from_utf8(&out.stdout).unwrap()).unwrap();
    assert_eq!(config["engine"]["include_sensitive"].as_bool(), Some(false));
}

#[test]
fn synthetic_multi_interface_capture_decodes_and_redacts_with_multiple_workers() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/clinical-network.pcapng");
    for workers in ["1", "4"] {
        let out = run(&[
            "analyze",
            fixture.to_str().unwrap(),
            "--workers",
            workers,
            "--format",
            "json",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let events: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
        let messages: Vec<_> = events.iter().filter_map(|e| e.get("message")).collect();
        assert_eq!(messages.len(), 12);
        for name in [
            "hl7", "astm", "poct", "dicom", "http", "http2", "dns", "quic",
        ] {
            assert!(
                messages.iter().any(|m| m["protocol"] == name),
                "missing {name}"
            );
        }
        assert!(
            messages
                .iter()
                .filter(|m| m["protocol"] == "hl7")
                .all(|m| m["fields"]["segments"] == "[redacted]")
        );
        let packets: u64 = events
            .iter()
            .filter_map(|e| e["counters"]["packets"].as_u64())
            .sum();
        assert_eq!(packets, 25);
    }
}
