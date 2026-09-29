"""Portable local verification; writes exact logs and a machine-readable summary."""
from pathlib import Path
import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("--seconds", type=int, default=60)
parser.add_argument("--skip-native", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = root / "artifacts" / "validation"
out.mkdir(parents=True, exist_ok=True)
results = []
def check(name, command, extra_env=None):
    print(f"Checking {name} ...", flush=True)
    started = time.monotonic()
    env = os.environ.copy()
    env.update(extra_env or {})
    with (out / f"{name}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    results.append({"name":name,"exit_code":result.returncode,"seconds":time.monotonic()-started,"command":command})
    if result.returncode:
        print((out / f"{name}.log").read_text(encoding="utf-8",errors="replace"))
        raise SystemExit(result.returncode)

check("format", ["cargo","fmt","--all","--","--check"])
check("clippy", ["cargo","clippy","--workspace","--all-targets","--locked","--","-D","warnings"])
check("tests", ["cargo","test","--workspace","--locked"])
check("docs", ["cargo","doc","--workspace","--no-deps","--locked"])
check("release", ["cargo","build","--release","--workspace","--locked"])
check("ffi", [sys.executable,"tools/verify_ffi.py"])
if not args.skip_native and sys.platform == "win32":
    check("cpp", ["cmd","/c","tools\\build_cpp.cmd"])
    check("capture-abi", ["cargo","test","-p","netkit","--test","capture_backend","--locked","--","--ignored"],
          {"NETKIT_TEST_PCAP":str(root/"artifacts"/"mock_pcap.dll")})
binary = str(root / "target" / "release" / ("netkit.exe" if sys.platform == "win32" else "netkit"))
check("doctor", [binary,"doctor","--format","json"])
check("fixture", [binary,"analyze","tests/fixtures/clinical-network.pcapng","--workers","4","--format","json"])
if args.seconds > 0:
    check("replay", [binary,"benchmark","tests/fixtures/scale.pcapng","--seconds",str(args.seconds),"--format","json"])
summary = {"recorded_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"platform":platform.platform(),"checks":results}
(out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
print(f"All {len(results)} checks passed. Logs: {out}",flush=True)
