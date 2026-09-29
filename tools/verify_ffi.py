"""Exercise the actual shared library through C ABI (not Rust-to-Rust calls)."""
from pathlib import Path
import ctypes as c
import json
import re
import sys

root = Path(__file__).resolve().parents[1]
library = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "target" / "release" / ("netkit_ffi.dll" if sys.platform == "win32" else "libnetkit_ffi.dylib" if sys.platform == "darwin" else "libnetkit_ffi.so")
lib = c.CDLL(str(library.resolve()))
exports = re.findall(r"\b(netkit_\w+)\s*\(", (root / "include" / "netkit.h").read_text())
for name in exports:
    assert getattr(lib, name), name
lib.netkit_abi_version.restype = c.c_uint32
assert lib.netkit_abi_version() == 1
lib.netkit_engine_new.argtypes = [c.c_char_p, c.POINTER(c.c_void_p)]
lib.netkit_decode_message.argtypes = [c.c_void_p, c.c_char_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_void_p)]
lib.netkit_engine_ingest.argtypes = [c.c_void_p,c.c_void_p,c.POINTER(c.c_void_p)]
lib.netkit_engine_finish.argtypes = [c.c_void_p,c.POINTER(c.c_void_p)]
lib.netkit_engine_free.argtypes = [c.c_void_p]
lib.netkit_string_free.argtypes = [c.c_void_p]
lib.netkit_last_error.restype = c.c_char_p
engine = c.c_void_p()
assert lib.netkit_engine_new(None, c.byref(engine)) == 0
try:
    payload = (root / "tests" / "fixtures" / "synthetic.hl7").read_bytes()
    buffer = c.create_string_buffer(payload)
    result = c.c_void_p()
    assert lib.netkit_decode_message(engine,b"hl7",buffer,len(payload),c.byref(result)) == 0, lib.netkit_last_error()
    decoded = json.loads(c.string_at(result))
    lib.netkit_string_free(result)
    assert decoded[0]["protocol"] == "hl7"
    assert decoded[0]["fields"]["segments"] == "[redacted]"
    class Packet(c.Structure):
        _fields_=[("timestamp_ns",c.c_uint64),("interface_id",c.c_uint32),("link_type",c.c_uint32),("original_len",c.c_uint32),("data",c.c_void_p),("data_len",c.c_size_t),("sensor",c.c_char_p)]
    tiny=c.create_string_buffer(b"\0")
    packet=Packet(1,1,999,1,c.cast(tiny,c.c_void_p),1,b"ffi-test")
    assert lib.netkit_engine_ingest(engine,c.byref(packet),c.byref(result)) == 0
    assert isinstance(json.loads(c.string_at(result)),list)
    lib.netkit_string_free(result)
    assert lib.netkit_engine_finish(engine,c.byref(result)) == 0
    lib.netkit_string_free(result)
finally:
    lib.netkit_engine_free(engine)
print(json.dumps({"abi":1,"exports_verified":len(exports),"shared_library":str(library),"message_decode":"passed","packet_ingest":"passed"}))
