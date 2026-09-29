//! Version 1 C ABI. Functions never unwind across the ABI boundary.
//! Handles are single-threaded: a caller must serialize calls for each handle.
//! Returned strings are owned by netKit and must be released with netkit_string_free.
use netkit::{Engine, EngineConfig, Error, Packet, Source};
use std::{
    cell::RefCell,
    ffi::{CStr, CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

/// Opaque analysis handle; never allocate or copy from C.
pub struct NetkitEngine {
    engine: Engine,
}
#[repr(C)]
pub struct NetkitPacket {
    pub timestamp_ns: u64,
    pub interface_id: u32,
    pub link_type: u32,
    pub original_len: u32,
    pub data: *const u8,
    pub data_len: usize,
    /// UTF-8, NUL terminated; NULL selects "ffi".
    pub sensor: *const c_char,
}
thread_local! {static LAST_ERROR:RefCell<CString>=RefCell::new(CString::new("").unwrap());}
fn error(message: impl ToString) {
    let s = message.to_string().replace('\0', "\\0");
    LAST_ERROR.with(|e| *e.borrow_mut() = CString::new(s).unwrap());
}
fn boundary<F: FnOnce() -> netkit::Result<()>>(f: F) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            error("");
            0
        }
        Ok(Err(e)) => {
            let code = match e {
                Error::Limit(_) => 3,
                Error::Unavailable(_) => 4,
                _ => 1,
            };
            error(e);
            code
        }
        Err(_) => {
            error("internal panic contained at netKit ABI boundary; discard this handle");
            2
        }
    }
}
unsafe fn input<'a>(p: *const c_char) -> netkit::Result<&'a str> {
    if p.is_null() {
        return Err(Error::Invalid("null string".into()));
    }
    // SAFETY: caller guarantees a valid NUL-terminated string for the call duration.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| Error::Invalid("input must be UTF-8".into()))
}
unsafe fn output<T: serde::Serialize>(value: &T, out: *mut *mut c_char) -> netkit::Result<()> {
    if out.is_null() {
        return Err(Error::Invalid("null output string pointer".into()));
    }
    let json = serde_json::to_string(value)?;
    let string = CString::new(json).map_err(|_| Error::Invalid("unexpected NUL in JSON".into()))?;
    // SAFETY: caller supplies a writable pointer-sized output location.
    unsafe {
        *out = string.into_raw();
    }
    Ok(())
}
/// The ABI contract version, independent of the package release version.
#[unsafe(no_mangle)]
pub extern "C" fn netkit_abi_version() -> u32 {
    1
}
/// Borrowed thread-local string, valid until the next netKit call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn netkit_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// # Safety
/// `out` must be writable; non-NULL config must point to NUL-terminated UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_engine_new(
    config_json: *const c_char,
    out: *mut *mut NetkitEngine,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    boundary(|| {
        if out.is_null() {
            return Err(Error::Invalid("null engine output pointer".into()));
        }
        let config = if config_json.is_null() {
            EngineConfig::default()
        } else {
            let raw = unsafe { input(config_json) }?;
            if raw.len() > 65536 {
                return Err(Error::Limit("configuration too large".into()));
            }
            serde_json::from_str(raw)?
        };
        let engine = Box::new(NetkitEngine {
            engine: Engine::new(config)?,
        });
        unsafe {
            *out = Box::into_raw(engine);
        }
        Ok(())
    })
}
/// # Safety
/// Handle must originate from netkit_engine_new and be exclusively borrowed.
/// Packet/data must remain valid until return. `out` is a writable string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_engine_ingest(
    handle: *mut NetkitEngine,
    packet: *const NetkitPacket,
    out: *mut *mut c_char,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    boundary(|| {
        if handle.is_null() || packet.is_null() || out.is_null() {
            return Err(Error::Invalid("null ingest argument".into()));
        }
        let handle = unsafe { &mut *handle };
        let packet = unsafe { &*packet };
        if packet.data_len > handle.engine.config().max_packet_bytes
            || packet.data_len > packet.original_len as usize
        {
            return Err(Error::Limit(
                "packet length exceeds configured/wire length".into(),
            ));
        }
        let data = if packet.data_len == 0 {
            Vec::new()
        } else {
            if packet.data.is_null() {
                return Err(Error::Invalid("null packet data".into()));
            }
            unsafe { std::slice::from_raw_parts(packet.data, packet.data_len) }.to_vec()
        };
        let sensor = if packet.sensor.is_null() {
            "ffi"
        } else {
            unsafe { input(packet.sensor) }?
        };
        if sensor.len() > 4096 {
            return Err(Error::Limit("sensor name too long".into()));
        }
        let events = handle.engine.ingest(&Packet {
            source: Source {
                sensor: sensor.into(),
                interface: packet.interface_id,
                link_type: packet.link_type,
            },
            timestamp_ns: packet.timestamp_ns,
            original_len: packet.original_len,
            data,
        });
        unsafe { output(&events, out) }
    })
}
/// # Safety
/// Handle must be valid and exclusively borrowed; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_engine_finish(
    handle: *mut NetkitEngine,
    out: *mut *mut c_char,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    boundary(|| {
        if handle.is_null() || out.is_null() {
            return Err(Error::Invalid("null finish argument".into()));
        }
        let events = unsafe { &mut *handle }.engine.finish();
        unsafe { output(&events, out) }
    })
}
/// # Safety
/// Handle must be valid and exclusively borrowed; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_engine_snapshot(
    handle: *mut NetkitEngine,
    out: *mut *mut c_char,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    boundary(|| {
        if handle.is_null() || out.is_null() {
            return Err(Error::Invalid("null snapshot argument".into()));
        }
        let e = &unsafe { &mut *handle }.engine;
        unsafe {
            output(
                &serde_json::json!({"statistics":e.statistics(),"devices":e.devices(),"flows":e.flows(),"buffered_bytes":e.buffered_bytes()}),
                out,
            )
        }
    })
}
/// # Safety
/// Valid, exclusively borrowed handle; readable protocol and bytes; writable out.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_decode_message(
    handle: *mut NetkitEngine,
    protocol: *const c_char,
    data: *const u8,
    data_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    if !out.is_null() {
        unsafe {
            *out = ptr::null_mut();
        }
    }
    boundary(|| {
        if handle.is_null() || out.is_null() {
            return Err(Error::Invalid("null decode argument".into()));
        }
        let e = &unsafe { &mut *handle }.engine;
        if data_len > e.config().max_message_bytes {
            return Err(Error::Limit("message too large".into()));
        }
        let data = if data_len == 0 {
            &[]
        } else {
            if data.is_null() {
                return Err(Error::Invalid("null data".into()));
            }
            unsafe { std::slice::from_raw_parts(data, data_len) }
        };
        let protocol = unsafe { input(protocol) }?;
        let messages = e.decode_message(protocol, data)?;
        unsafe { output(&messages, out) }
    })
}
/// # Safety
/// Non-NULL string must be an unreleased pointer returned by netKit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_string_free(value: *mut c_char) {
    if !value.is_null() {
        unsafe {
            drop(CString::from_raw(value));
        }
    }
}
/// # Safety
/// Non-NULL handle must originate from netkit_engine_new, not previously freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn netkit_engine_free(handle: *mut NetkitEngine) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle));
        }
    }
}
