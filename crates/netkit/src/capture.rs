//! Dynamically loaded libpcap/Npcap backend. Native pointers never escape this
//! module. Handles are thread-confined; each capture worker opens its own handle.
use crate::{Error, Packet, Result, Source};
use libloading::Library;
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: u32,
}
#[repr(C)]
struct TimeVal {
    seconds: libc::c_long,
    micros: libc::c_long,
}
#[repr(C)]
struct Header {
    time: TimeVal,
    caplen: u32,
    len: u32,
}
#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *mut c_void,
}
type Handle = *mut c_void;
type Find = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type Free = unsafe extern "C" fn(*mut PcapIf);
type Create = unsafe extern "C" fn(*const c_char, *mut c_char) -> Handle;
type Close = unsafe extern "C" fn(Handle);
type Set = unsafe extern "C" fn(Handle, c_int) -> c_int;
type Query = unsafe extern "C" fn(Handle) -> c_int;
type ErrorString = unsafe extern "C" fn(Handle) -> *mut c_char;
type Next = unsafe extern "C" fn(Handle, *mut *const Header, *mut *const u8) -> c_int;
type Nonblock = unsafe extern "C" fn(Handle, c_int, *mut c_char) -> c_int;
type Compile = unsafe extern "C" fn(Handle, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type SetFilter = unsafe extern "C" fn(Handle, *mut BpfProgram) -> c_int;
type FreeCode = unsafe extern "C" fn(*mut BpfProgram);
type Stats = unsafe extern "C" fn(Handle, *mut u32) -> c_int;
type Version = unsafe extern "C" fn() -> *const c_char;

struct Api {
    _library: Library,
    find: Find,
    free: Free,
    create: Create,
    close: Close,
    set_snaplen: Set,
    set_promisc: Set,
    set_timeout: Set,
    set_buffer: Set,
    set_rfmon: Set,
    can_rfmon: Query,
    activate: Query,
    datalink: Query,
    geterr: ErrorString,
    next: Next,
    nonblock: Nonblock,
    compile: Compile,
    filter: SetFilter,
    freecode: FreeCode,
    stats: Stats,
    version: Version,
}
#[derive(Clone)]
pub struct Pcap {
    api: Arc<Api>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub id: usize,
    pub name: String,
    pub description: Option<String>,
    pub loopback: bool,
    pub up: bool,
    pub wireless: bool,
    pub monitor_mode: Option<bool>,
}
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    pub interface: String,
    pub sensor: String,
    pub interface_id: u32,
    pub snaplen: u32,
    pub promiscuous: bool,
    pub monitor: bool,
    pub buffer_bytes: u32,
    pub filter: Option<String>,
}
impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            interface: String::new(),
            sensor: "local".into(),
            interface_id: 0,
            snaplen: 262144,
            promiscuous: true,
            monitor: false,
            buffer_bytes: 4 * 1024 * 1024,
            filter: None,
        }
    }
}
pub struct Capture {
    api: Arc<Api>,
    handle: Handle,
    source: Source,
    snaplen: u32,
    pub activation_warning: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatistics {
    pub received: u32,
    pub dropped: u32,
    pub interface_dropped: u32,
}

fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::Invalid("string contains NUL".into()))
}
// SAFETY: only used with valid libpcap-owned NUL-terminated strings or our error buffers.
unsafe fn string(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}
impl Pcap {
    pub fn load() -> Result<Self> {
        Self::load_from(None)
    }
    pub fn load_from(path: Option<&Path>) -> Result<Self> {
        let candidates: Vec<PathBuf> = if let Some(path) = path {
            if !path.is_absolute() {
                return Err(Error::Invalid(
                    "native library override must be an absolute path".into(),
                ));
            }
            vec![path.into()]
        } else {
            #[cfg(windows)]
            {
                let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
                vec![
                    PathBuf::from(root)
                        .join("System32")
                        .join("Npcap")
                        .join("wpcap.dll"),
                ]
            }
            #[cfg(target_os = "macos")]
            {
                vec![
                    "/usr/lib/libpcap.A.dylib".into(),
                    "/usr/lib/libpcap.dylib".into(),
                ]
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                vec![
                    "libpcap.so.1".into(),
                    "libpcap.so.0.8".into(),
                    "libpcap.so".into(),
                ]
            }
        };
        let mut failures = Vec::new();
        for path in candidates {
            // SAFETY: loading native executable code is an explicit backend boundary.
            // Windows searches only this DLL's directory and the system directory.
            let loaded = unsafe {
                #[cfg(windows)]
                {
                    libloading::os::windows::Library::load_with_flags(&path, 0x100 | 0x800)
                        .map(Library::from)
                }
                #[cfg(not(windows))]
                {
                    Library::new(&path)
                }
            };
            let library = match loaded {
                Ok(v) => v,
                Err(e) => {
                    failures.push(format!("{}: {e}", path.display()));
                    continue;
                }
            };
            // SAFETY: signatures match the stable libpcap C API. Function pointers
            // remain valid because Api owns Library and capture handles own Arc<Api>.
            unsafe {
                macro_rules! symbol {
                    ($name:literal,$ty:ty) => {
                        *library
                            .get::<$ty>(concat!($name, "\0").as_bytes())
                            .map_err(|e| {
                                Error::Unavailable(format!("libpcap API {}: {e}", $name))
                            })?
                    };
                }
                let api = Api {
                    find: symbol!("pcap_findalldevs", Find),
                    free: symbol!("pcap_freealldevs", Free),
                    create: symbol!("pcap_create", Create),
                    close: symbol!("pcap_close", Close),
                    set_snaplen: symbol!("pcap_set_snaplen", Set),
                    set_promisc: symbol!("pcap_set_promisc", Set),
                    set_timeout: symbol!("pcap_set_timeout", Set),
                    set_buffer: symbol!("pcap_set_buffer_size", Set),
                    set_rfmon: symbol!("pcap_set_rfmon", Set),
                    can_rfmon: symbol!("pcap_can_set_rfmon", Query),
                    activate: symbol!("pcap_activate", Query),
                    datalink: symbol!("pcap_datalink", Query),
                    geterr: symbol!("pcap_geterr", ErrorString),
                    next: symbol!("pcap_next_ex", Next),
                    nonblock: symbol!("pcap_setnonblock", Nonblock),
                    compile: symbol!("pcap_compile", Compile),
                    filter: symbol!("pcap_setfilter", SetFilter),
                    freecode: symbol!("pcap_freecode", FreeCode),
                    stats: symbol!("pcap_stats", Stats),
                    version: symbol!("pcap_lib_version", Version),
                    _library: library,
                };
                return Ok(Self { api: Arc::new(api) });
            }
        }
        Err(Error::Unavailable(format!(
            "libpcap/Npcap not available. Install libpcap on Unix or Npcap separately on Windows. File analysis still works. {}",
            failures.join("; ")
        )))
    }
    pub fn version(&self) -> String {
        unsafe { string((self.api.version)()) }
    }
    pub fn interfaces(&self) -> Result<Vec<Interface>> {
        let mut list = ptr::null_mut();
        let mut error = [0 as c_char; 256];
        // SAFETY: list and error are valid out-parameters. Iterate until NULL and
        // release exactly once, after copying all strings and flags.
        unsafe {
            if (self.api.find)(&mut list, error.as_mut_ptr()) != 0 {
                return Err(Error::Capture(string(error.as_ptr())));
            }
            struct Guard<'a> {
                api: &'a Api,
                list: *mut PcapIf,
            }
            impl Drop for Guard<'_> {
                fn drop(&mut self) {
                    unsafe { (self.api.free)(self.list) }
                }
            }
            let guard = Guard {
                api: &self.api,
                list,
            };
            let mut current = list;
            let mut out = Vec::new();
            while !current.is_null() {
                let d = &*current;
                let name = string(d.name);
                let h = (self.api.create)(d.name, error.as_mut_ptr());
                let monitor_mode = if h.is_null() {
                    None
                } else {
                    let result = (self.api.can_rfmon)(h);
                    (self.api.close)(h);
                    if result < 0 { None } else { Some(result == 1) }
                };
                out.push(Interface {
                    id: out.len() + 1,
                    name,
                    description: if d.description.is_null() {
                        None
                    } else {
                        Some(string(d.description))
                    },
                    loopback: d.flags & 1 != 0,
                    up: d.flags & 2 != 0,
                    wireless: d.flags & 8 != 0,
                    monitor_mode,
                });
                current = d.next;
            }
            drop(guard);
            Ok(out)
        }
    }
    pub fn open(&self, options: &CaptureOptions) -> Result<Capture> {
        if options.snaplen == 0
            || options.snaplen > 16 * 1024 * 1024
            || options.buffer_bytes == 0
            || options.buffer_bytes > i32::MAX as u32
        {
            return Err(Error::Invalid(
                "invalid capture buffer/snapshot length".into(),
            ));
        }
        let name = cstring(&options.interface)?;
        let mut error = [0 as c_char; 256];
        // SAFETY: handle ownership immediately transfers to Capture; early returns
        // invoke Drop. All configuration occurs before activation.
        unsafe {
            let handle = (self.api.create)(name.as_ptr(), error.as_mut_ptr());
            if handle.is_null() {
                return Err(Error::Capture(string(error.as_ptr())));
            }
            let mut capture = Capture {
                api: self.api.clone(),
                handle,
                source: Source {
                    sensor: options.sensor.clone(),
                    interface: options.interface_id,
                    link_type: 0,
                },
                snaplen: options.snaplen,
                activation_warning: None,
            };
            for (set, value) in [
                (self.api.set_snaplen, options.snaplen as i32),
                (self.api.set_promisc, i32::from(options.promiscuous)),
                (self.api.set_timeout, 100),
                (self.api.set_buffer, options.buffer_bytes as i32),
            ] {
                if set(handle, value) != 0 {
                    return Err(capture.error());
                }
            }
            if options.monitor {
                if (self.api.can_rfmon)(handle) != 1 {
                    return Err(Error::Unavailable(
                        "monitor mode is not supported by this interface/driver".into(),
                    ));
                }
                if (self.api.set_rfmon)(handle, 1) != 0 {
                    return Err(capture.error());
                }
            }
            let activated = (self.api.activate)(handle);
            if activated < 0 {
                return Err(capture.error());
            }
            if activated > 0 {
                capture.activation_warning = Some(format!(
                    "libpcap activation warning {activated}: {}",
                    string((self.api.geterr)(handle))
                ));
            }
            let link = (self.api.datalink)(handle);
            if link < 0 {
                return Err(capture.error());
            }
            capture.source.link_type = link as u32;
            if (self.api.nonblock)(handle, 1, error.as_mut_ptr()) != 0 {
                return Err(Error::Capture(string(error.as_ptr())));
            }
            if let Some(filter) = &options.filter {
                let expression = cstring(filter)?;
                let mut program = BpfProgram {
                    len: 0,
                    insns: ptr::null_mut(),
                };
                if (self.api.compile)(handle, &mut program, expression.as_ptr(), 1, 0xffffffff) != 0
                {
                    return Err(capture.error());
                }
                let result = (self.api.filter)(handle, &mut program);
                (self.api.freecode)(&mut program);
                if result != 0 {
                    return Err(capture.error());
                }
            }
            Ok(capture)
        }
    }
}
impl Capture {
    fn error(&self) -> Error {
        Error::Capture(unsafe { string((self.api.geterr)(self.handle)) })
    }
    pub fn source(&self) -> &Source {
        &self.source
    }
    /// Nonblocking poll. None means no packet is currently available.
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        let mut header = ptr::null();
        let mut bytes = ptr::null();
        // SAFETY: pcap_next_ex provides memory valid until the next pcap call.
        // Validate lengths and copy immediately before returning to the caller.
        unsafe {
            match (self.api.next)(self.handle, &mut header, &mut bytes) {
                0 | -2 => Ok(None),
                1 => {
                    if header.is_null() || bytes.is_null() {
                        return Err(Error::Capture("backend returned null packet".into()));
                    }
                    let h = &*header;
                    if h.caplen > self.snaplen
                        || h.caplen > h.len
                        || h.time.seconds < 0
                        || !(0..1_000_000).contains(&h.time.micros)
                    {
                        return Err(Error::Capture(
                            "backend returned invalid packet metadata".into(),
                        ));
                    }
                    let timestamp_ns = (h.time.seconds as u64)
                        .checked_mul(1_000_000_000)
                        .and_then(|v| v.checked_add(h.time.micros as u64 * 1000))
                        .ok_or_else(|| Error::Capture("timestamp overflow".into()))?;
                    Ok(Some(Packet {
                        source: self.source.clone(),
                        timestamp_ns,
                        original_len: h.len,
                        data: std::slice::from_raw_parts(bytes, h.caplen as usize).to_vec(),
                    }))
                }
                _ => Err(self.error()),
            }
        }
    }
    pub fn statistics(&self) -> Result<CaptureStatistics> {
        // Npcap adds ps_capt after the three common fields. Allocate extra room;
        // only fields guaranteed by the portable API are read.
        let mut values = [0u32; 8];
        unsafe {
            if (self.api.stats)(self.handle, values.as_mut_ptr()) != 0 {
                return Err(self.error());
            }
        }
        Ok(CaptureStatistics {
            received: values[0],
            dropped: values[1],
            interface_dropped: values[2],
        })
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.handle) }
    }
}
