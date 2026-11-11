#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Recover native inputs and check the real generator's packaged headers."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import re
import shutil
import stat
import subprocess
import zipfile

ORIGINAL_REF = "1484045d2d841ff78666238fd11a3cfc637e4ab4"
GENERATOR_REF = "e9adebbe086a75697724c2570ce37ba3d0aa1574"
FIX_REF = "5bfd9a6430f7ea0fb1141f08d338215d8e61aa48"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(path):
    value = PurePosixPath(path)
    if value.is_absolute() or ".." in value.parts or "\\" in path:
        raise ValueError(f"unsafe artifact path: {path}")
    return value


def zip_header_failures(archive):
    with zipfile.ZipFile(archive) as payload:
        members = set(payload.namelist())
        maps = sorted(name for name in members if name.endswith("/module.modulemap"))
        if not maps:
            raise ValueError(f"no module maps: {archive}")
        failures = []
        for module in maps:
            references = re.findall(r'^\s*header "([^"]+)"', payload.read(module).decode(), re.M)
            if not references:
                raise ValueError(f"empty module map: {module}")
            for reference in references:
                target = posixpath.normpath(posixpath.join(posixpath.dirname(module), reference))
                if target not in members:
                    failures.append({"module": module, "reference": reference})
        return failures


def prepare(artifact, source, proof):
    original = artifact / "_temp/native-proof"
    saved = artifact / "AppleMobileDeviceLibrary/AppleMobileDeviceLibrary/build"
    proof.mkdir(parents=True, exist_ok=True)
    if subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip() != GENERATOR_REF:
        raise ValueError("unexpected production generator revision")
    for line in (original / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split(maxsplit=1)
        path = original / relative(name.strip())
        if digest(path) != expected:
            raise ValueError(f"original checksum differs: {name}")
    manifest = original / "Licenses/manifest.json"
    context = json.loads(manifest.read_text())
    wrapper = next(item for item in context["components"] if item["name"] == "AppleMobileDeviceLibrary")
    if wrapper["revision"] != ORIGINAL_REF:
        raise ValueError("compiled wrapper context differs")
    build = source / "build"
    build.mkdir()
    for prefix in ("build", "build.arm64", "build.x86_64"):
        shutil.copytree(saved / prefix / "Licenses", build / prefix / "Licenses")
    libraries = build / "build/lib"
    libraries.mkdir()
    library_hashes = {}
    for library in sorted((saved / "build/lib").glob("*.a")):
        if not stat.S_ISREG(library.lstat().st_mode):
            raise ValueError(f"nonregular library: {library}")
        shutil.copy2(library, libraries / library.name)
        library_hashes[library.name] = digest(library)
    if not library_hashes:
        raise ValueError("native libraries are missing")
    include = build / "build.arm64/include"
    include.mkdir()
    header_hashes = {}
    original_failures = {}
    archives = sorted((original / "AppleMobileDeviceLibrary/BinaryTargets").glob("*.xcframework.zip"))
    if len(archives) != 6:
        raise ValueError("expected six original XCFramework archives")
    for archive in archives:
        failures = zip_header_failures(archive)
        if not failures:
            raise ValueError(f"original regression was not reproduced: {archive}")
        original_failures[archive.name] = failures
        with zipfile.ZipFile(archive) as payload:
            root = archive.name.removesuffix(".zip")
            info = plistlib.loads(payload.read(f"{root}/Info.plist"))
            for library in info["AvailableLibraries"]:
                if library["SupportedPlatform"] != "macos":
                    raise ValueError("unexpected input platform")
                prefix = f'{root}/{library["LibraryIdentifier"]}/{library["HeadersPath"]}/'
                for entry in payload.infolist():
                    if not entry.filename.startswith(prefix) or not entry.filename.endswith(".h"):
                        continue
                    if not stat.S_ISREG(entry.external_attr >> 16):
                        raise ValueError(f"nonregular header: {entry.filename}")
                    name = str(relative(entry.filename.removeprefix(prefix)))
                    destination = include / name
                    contents = payload.read(entry)
                    if destination.exists() and destination.read_bytes() != contents:
                        raise ValueError(f"inconsistent shared header: {name}")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(contents)
                    header_hashes[name] = hashlib.sha256(contents).hexdigest()
    for filename in ("build-context.txt", "toolchain-context.txt", "SHA256SUMS", "src.version"):
        shutil.copy2(original / filename, proof / f"original-{filename}")
    shutil.copy2(manifest, proof / "original-manifest.json")
    record = {
        "test_artifacts_only": True,
        "native_libraries_rebuilt": False,
        "original_run": 43055257192,
        "original_artifact_id": 13870814996,
        "original_compilation_source": ORIGINAL_REF,
        "original_manifest_sha256": digest(manifest),
        "generator_source": GENERATOR_REF,
        "isolated_generator_fix": FIX_REF,
        "validation_workflow_source": os.environ.get("GITHUB_SHA"),
        "native_library_sha256": library_hashes,
        "recovered_header_sha256": header_hashes,
        "original_missing_headers": original_failures,
    }
    (proof / "generator-provenance.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Recovered original native libraries and headers; all six original module maps reproduce the failure.")


def verify(source, proof):
    record = json.loads((proof / "generator-provenance.json").read_text())
    build = source / "build"
    for name, expected in record["native_library_sha256"].items():
        if digest(build / "build/lib" / name) != expected:
            raise ValueError(f"native library changed: {name}")
    for name, expected in record["recovered_header_sha256"].items():
        if digest(build / "build.arm64/include" / name) != expected:
            raise ValueError(f"header input changed: {name}")
    original_manifest = (proof / "original-manifest.json").read_bytes()
    outputs = sorted((build / "build.spm/BinaryTargets").glob("*.xcframework.zip"))
    if len(outputs) != 6:
        raise ValueError("expected six regenerated archives")
    for archive in outputs:
        failures = zip_header_failures(archive)
        if failures:
            raise ValueError(f"unresolved generated header: {failures[0]}")
        with zipfile.ZipFile(archive) as payload:
            root = archive.name.removesuffix(".zip")
            if payload.read(f"{root}/Licenses/manifest.json") != original_manifest:
                raise ValueError(f"compiled manifest was changed: {archive}")
            for name in payload.namelist():
                if name.endswith("/module.modulemap"):
                    generated = build / "build.frameworks" / relative(name)
                    if generated.read_bytes() != payload.read(name):
                        raise ValueError(f"framework and package module maps differ: {name}")
        print(f"{archive.name}: every quoted header resolves; original compiled manifest preserved")
    if (build / "build.spm/Licenses/manifest.json").read_bytes() != original_manifest:
        raise ValueError("package compiled manifest was changed")


parser = argparse.ArgumentParser()
parser.add_argument("command", choices=("prepare", "verify"))
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--proof", required=True, type=Path)
parser.add_argument("--artifact", type=Path)
args = parser.parse_args()
if args.command == "prepare":
    if args.artifact is None:
        parser.error("prepare requires --artifact")
    prepare(args.artifact.resolve(), args.source.resolve(), args.proof.resolve())
else:
    verify(args.source.resolve(), args.proof.resolve())
