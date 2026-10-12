#!/usr/bin/env python3
"""Package the MIT runtime with dependency notices; never install or publish it."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OVERRIDES = {
    "jsonschema-regex": "jsonschema-LICENSE", "jsonschema-value": "jsonschema-LICENSE",
    "rmcp": "rust-sdk-LICENSE", "rmcp-macros": "rust-sdk-LICENSE",
    "uuid-simd": "simd-LICENSE", "vsimd": "simd-LICENSE",
}


def run(*argv):
    return subprocess.check_output(argv, cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def notices(package, swift_checkout):
    metadata = json.loads(run("cargo", "metadata", "--locked", "--offline", "--format-version", "1",
                              "--filter-platform", "aarch64-apple-darwin"))
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]
    visited = set()

    def visit(identity):
        if identity in visited:
            return
        visited.add(identity)
        for dep in nodes[identity]["deps"]:
            if any(k["kind"] != "dev" for k in dep["dep_kinds"]):
                visit(dep["pkg"])

    visit(root)
    extras = ROOT / "docs/distribution/upstream-licenses"
    upstream = json.loads((extras / "sources.json").read_text())
    for entry in upstream:
        if digest(extras / entry["file"]) != entry["sha256"]:
            raise ValueError("Pinned upstream notice hash mismatch")
    inventory = []
    for crate in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if crate["id"] == root or crate["id"] not in visited:
            continue
        if not crate.get("license"):
            raise ValueError(f"Missing license expression: {crate['name']}")
        directory = Path(crate["manifest_path"]).parent
        files = sorted(p for p in directory.iterdir() if p.is_file() and
                       p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")))
        source = "packaged crate notices"
        if not files and crate["name"] in OVERRIDES:
            override = extras / OVERRIDES[crate["name"]]
            files = [override]
            source = next(e["url"] for e in upstream if e["file"] == override.name)
            vcs = json.loads((directory / ".cargo_vcs_info.json").read_text())
            if vcs["git"]["sha1"] not in source:
                raise ValueError(f"Notice override revision mismatch: {crate['name']}")
        if not files:
            raise ValueError(f"Missing license text: {crate['name']}")
        dest = package / "notices" / f"{crate['name']}-{crate['version']}"
        dest.mkdir(parents=True)
        for item in files:
            shutil.copyfile(item, dest / item.name)
        inventory.append(dict(name=crate["name"], version=crate["version"],
                              license=crate["license"], repository=crate.get("repository"),
                              noticeSource=source,
                              files=[str((dest / p.name).relative_to(package)) for p in files]))
    rustroot = Path(run("rustc", "--print", "sysroot")) / "share/doc/rust"
    rustdest = package / "notices/rust-standard-library"
    shutil.copytree(rustroot / "licenses", rustdest / "licenses")
    shutil.copyfile(rustroot / "COPYRIGHT-library.html", rustdest / "COPYRIGHT-library.html")
    swift_revision = run("git", "-C", str(swift_checkout), "rev-parse", "HEAD")
    pin = json.loads((ROOT / "tools/acp-swift-checks/Package.resolved").read_text())["pins"][0]
    if swift_revision != pin["state"]["revision"]:
        raise ValueError("SwiftSyntax notice checkout does not match Package.resolved")
    shutil.copyfile(swift_checkout / "LICENSE.txt", package / "SwiftSyntax-LICENSE.txt")
    inventory.append(dict(name="swift-syntax", version=pin["state"]["version"], revision=swift_revision,
                          license="Apache-2.0 WITH Swift-exception", files=["SwiftSyntax-LICENSE.txt"]))
    (package / "DEPENDENCIES.json").write_text(json.dumps(inventory, indent=2) + "\n")
    rows = ["# Third-party notices", "", "This package includes the original license texts in `notices/` and",
            "`SwiftSyntax-LICENSE.txt`. Components retain their own terms. The Rust list conservatively",
            "covers the target-filtered normal/build dependency closure, including compile-time helpers;",
            "it is not a claim that every listed crate contributes executable bytes. No third-party",
            "source is redistributed here. Rust standard-library copyright and license files are included.",
            "Swift system libraries are supplied by macOS, not copied into this package.", "",
            "| Component | Version | Declared license |", "|---|---|---|"]
    rows += [f"| {x['name']} | {x['version']} | {x['license']} |" for x in inventory]
    (package / "THIRD-PARTY-NOTICES.md").write_text("\n".join(rows) + "\n")
    return len(inventory) - 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("cli", "analyzer", "swift-checkout", "output", "release-id"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--public-preview", action="store_true",
                        help="Label an explicitly authorized public preview; does not sign, notarize or upload")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,64}", args.release_id):
        parser.error("release-id must be a bounded filename component")
    output = Path(args.output).resolve()
    if output.exists():
        parser.error("output already exists; use a new directory")
    cli, analyzer = Path(args.cli).resolve(), Path(args.analyzer).resolve()
    if not cli.is_file() or not analyzer.is_file():
        parser.error("both compiled executables are required")
    if run("lipo", "-archs", str(cli)) != "arm64":
        parser.error("this candidate packager requires an arm64-only CLI")
    output.mkdir(parents=True)
    package = output / ("ACP-runtime-" + args.release_id)
    package.mkdir()
    input_hashes = {"cli": digest(cli), "analyzer": digest(analyzer)}
    for source, name in ((cli, "acp"), (analyzer, "acp-swift-checks")):
        dest = package / name
        shutil.copyfile(source, dest)
        dest.chmod(0o755)
        run("strip", "-S", str(dest))
        if b"/Users/" in dest.read_bytes():
            raise ValueError(f"Private build path remains in {name}; rebuild with path remapping")
        run("codesign", "--force", "--sign", "-", str(dest))
        run("codesign", "--verify", "--strict", str(dest))
    count = notices(package, Path(args.swift_checkout).resolve())
    shutil.copyfile(ROOT / "LICENSE", package / "LICENSE")
    shutil.copyfile(ROOT / "docs/INSTALLATION.md", package / "INSTALLATION.md")
    status = "public-preview" if args.public_preview else "development-candidate-awaiting-final-verification"
    record = dict(releaseId=args.release_id, status=status,
                  signing="ad-hoc; not Developer ID signed or notarized", cliArchitecture="arm64",
                  analyzerArchitectures=run("lipo", "-archs", str(package / "acp-swift-checks")),
                  cliVersion=run(str(package / "acp"), "--version"),
                  analyzerVersion=run(str(package / "acp-swift-checks"), "--version"),
                  rust=run("rustc", "--version"), sourceRevision=run("git", "rev-parse", "HEAD"),
                  cargoLockSha256=digest(ROOT / "Cargo.lock"), inputSha256=input_hashes,
                  normalAndBuildCrates=count, runtimeSourceIncluded=False, license="MIT",
                  sourceRepository="https://github.com/Vvlladd/acp-core")
    (package / "RELEASE.json").write_text(json.dumps(record, indent=2) + "\n")
    files = sorted(p for p in package.rglob("*") if p.is_file())
    (package / "SHA256SUMS.txt").write_text("".join(f"{digest(p)}  {p.relative_to(package)}\n" for p in files))
    archive = output / f"ACP-runtime-{args.release_id}-macos-arm64.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(package.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(output))
    (output / "SHA256SUMS.txt").write_text(f"{digest(archive)}  {archive.name}\n")
    print(json.dumps(dict(archive=str(archive), sha256=digest(archive), normalAndBuildCrates=count), indent=2))


if __name__ == "__main__":
    main()
