"""Build a local SDK ZIP from existing release artifacts; never publishes."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import subprocess
import sys
import zipfile

root = Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument("--overwrite",action="store_true",help="Replace the local SDK archive from a previous build")
args=parser.parse_args()
system = {"win32":"windows","darwin":"macos"}.get(sys.platform,"linux")
destination = root / "artifacts" / f"netKit-{system}-{platform.machine().lower()}.zip"
destination.parent.mkdir(exist_ok=True)
if destination.exists() and not args.overwrite:
    raise SystemExit(f"Refusing to overwrite existing package: {destination}")
metadata = json.loads(subprocess.check_output(["cargo","metadata","--format-version","1","--locked"],cwd=root,text=True))
files = {}
release = root / "target" / "release"
binary = "netkit.exe" if sys.platform == "win32" else "netkit"
if not (release/binary).is_file():
    raise SystemExit("Run cargo build --release --workspace first")
for name in [binary,"netkit_ffi.dll","netkit_ffi.dll.lib","netkit_ffi.lib","libnetkit_ffi.so","libnetkit_ffi.dylib","libnetkit_ffi.a"]:
    if (release/name).is_file(): files[f"bin/{name}"] = release/name
for name in ["README.md","LICENSE-MIT","LICENSE-APACHE","SECURITY.md","CONTRIBUTING.md","Cargo.lock","Cargo.toml","netkit.example.toml",".gitignore",".gitattributes"]:
    files[name] = root/name
for folder in ["include","docs","examples/cpp","tests/fixtures","crates","tools",".github"]:
    for path in (root/folder).rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts: files[path.relative_to(root).as_posix()] = path
for path in [root/"fuzz"/"Cargo.toml",root/"fuzz"/"Cargo.lock",root/"fuzz"/"README.md",*(root/"fuzz"/"fuzz_targets").glob("*.rs")]:
    files[path.relative_to(root).as_posix()] = path
third_party=[]
for package in metadata["packages"]:
    if package["source"] is None: continue
    package_root=Path(package["manifest_path"]).parent
    license_files=[]
    candidates=list(package_root.iterdir())
    if package.get("license_file"):
        candidates.append(package_root/package["license_file"])
    for path in candidates:
        if path.is_file() and (path.name.upper().startswith(("LICENSE","LICENCE","COPYING","NOTICE")) or path.name==package.get("license_file")):
            name=f"licenses/{package['name']}-{package['version']}/{path.name}"
            files[name]=path;license_files.append(name)
    third_party.append({"name":package["name"],"version":package["version"],"license":package["license"],"files":license_files})
with zipfile.ZipFile(destination,"w" if args.overwrite else "x",zipfile.ZIP_DEFLATED) as archive:
    for name,path in sorted(files.items()): archive.write(path,f"netKit/{name}")
    archive.writestr("netKit/THIRD_PARTY.json",json.dumps(third_party,indent=2)+"\n")
    archive.writestr("netKit/START.txt","Run bin/netkit doctor (Windows: bin/netkit.exe).\nThis is a local validation build, not a certified release. See docs/VALIDATION.md.\nNpcap and TShark are not bundled. All capture fixtures are synthetic.\n")
digest=hashlib.sha256(destination.read_bytes()).hexdigest()
destination.with_suffix(".zip.sha256").write_text(f"{digest}  {destination.name}\n",encoding="ascii")
print(json.dumps({"path":str(destination),"sha256":digest,"bytes":destination.stat().st_size,"license_entries":len(third_party),"packages_without_license_file":[p["name"] for p in third_party if not p["files"]]}))
