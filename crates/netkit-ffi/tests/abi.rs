use netkit_ffi::*;
use std::{
    ffi::{CStr, CString},
    ptr,
};

#[test]
fn abi_lifecycle_json_ownership_and_null_errors() {
    unsafe {
        assert_eq!(netkit_abi_version(), 1);
        assert_ne!(netkit_engine_new(ptr::null(), ptr::null_mut()), 0);
        let mut handle = ptr::null_mut();
        assert_eq!(netkit_engine_new(ptr::null(), &mut handle), 0);
        assert!(!handle.is_null());
        let msg = b"\x0bMSH|^~\\&|D|L|N|T|20260929||ORU^R01|ABI-1|P|2.5\rPID|1||SECRET\r\x1c\r";
        let name = CString::new("hl7").unwrap();
        let mut result = ptr::null_mut();
        assert_eq!(
            netkit_decode_message(handle, name.as_ptr(), msg.as_ptr(), msg.len(), &mut result),
            0
        );
        let text = CStr::from_ptr(result).to_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed[0]["protocol"], "hl7");
        assert!(!text.contains("SECRET"));
        netkit_string_free(result);
        assert_eq!(netkit_engine_snapshot(handle, &mut result), 0);
        assert!(
            serde_json::from_str::<serde_json::Value>(CStr::from_ptr(result).to_str().unwrap())
                .is_ok()
        );
        netkit_string_free(result);
        let bad = NetkitPacket {
            timestamp_ns: 0,
            interface_id: 1,
            link_type: 1,
            original_len: 64,
            data: ptr::null(),
            data_len: 64,
            sensor: ptr::null(),
        };
        assert_ne!(netkit_engine_ingest(handle, &bad, &mut result), 0);
        assert!(result.is_null());
        assert!(!CStr::from_ptr(netkit_last_error()).to_bytes().is_empty());
        assert_eq!(netkit_engine_finish(handle, &mut result), 0);
        netkit_string_free(result);
        netkit_engine_free(handle);
        netkit_engine_free(ptr::null_mut());
        netkit_string_free(ptr::null_mut());
    }
}
#[test]
fn ffi_packet_layout_matches_c_abi_contract() {
    assert_eq!(std::mem::offset_of!(NetkitPacket, timestamp_ns), 0);
    assert_eq!(std::mem::offset_of!(NetkitPacket, interface_id), 8);
    assert_eq!(std::mem::offset_of!(NetkitPacket, link_type), 12);
    assert_eq!(std::mem::offset_of!(NetkitPacket, original_len), 16);
    if cfg!(target_pointer_width = "64") {
        assert_eq!(std::mem::offset_of!(NetkitPacket, data), 24);
        assert_eq!(std::mem::size_of::<NetkitPacket>(), 48);
    }
}
