#!/usr/bin/env python3
"""Real-process acceptance test for portable native setup (no mock proof)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


def run(executable, root):
    env = dict(os.environ)
    env.pop("LKTRS_STATE_PATH", None)

    def call(*args, succeeds=True):
        result = subprocess.run([str(executable), *map(str, args)], capture_output=True,
                                env=env, stdin=subprocess.DEVNULL, timeout=1200)
        if succeeds:
            if result.returncode:
                raise AssertionError(result.stderr.decode(errors="replace"))
            return json.loads(result.stdout)
        if result.returncode == 0:
            raise AssertionError(f"invalid input accepted: {args}")
        if b'"verified":true' in result.stdout:
            raise AssertionError("failed command emitted success")
        return result.stderr.decode(errors="replace")

    full, public, sample = root / "full", root / "public", root / "sample"
    created = call("setup", "--out", full, "--capacity", 4)
    pin = created["manifest_sha256"]
    manifest = json.loads((full / "manifest.json").read_text())
    assert hashlib.sha256((full / "manifest.json").read_bytes()).hexdigest() == pin
    assert set(p.name for p in full.iterdir()) == {"manifest.json", "parameters.bin", "pk.bin", "vk.bin"}
    call("export-public", "--setup", full, "--manifest-sha256", pin, "--out", public)
    assert set(p.name for p in public.iterdir()) == {"manifest.json", "parameters.bin", "vk.bin"}
    assert (public / "manifest.json").read_bytes() == (full / "manifest.json").read_bytes()
    # Corrupt the large PK in place; a rejected load must not silently run a new
    # setup or publish an example. Avoid duplicating a hundreds-of-MB key.
    key_path = full / "pk.bin"
    with key_path.open("r+b") as key:
        key.seek(-1, 2)
        original_byte = key.read(1)
        key.seek(-1, 2)
        key.write(bytes([original_byte[0] ^ 1]))
    try:
        call("sample", "--setup", full, "--manifest-sha256", pin,
             "--out", root / "corrupt-pk", succeeds=False)
        assert not (root / "corrupt-pk").exists()
    finally:
        with key_path.open("r+b") as key:
            key.seek(-1, 2)
            key.write(original_byte)
    generated = call("sample", "--setup", full, "--manifest-sha256", pin, "--out", sample)
    assert generated["vk_sha256"] == manifest["verifying_key"]["sha256"]
    context = json.loads((sample / "context.json").read_text())
    assert set(context) == {"format", "issue", "k", "accounts"}
    assert all(set(a) == {"u", "y"} for a in context["accounts"])
    assert set(p.name for p in sample.iterdir()) == {"context.json", "message.bin", "signature.bin"}

    # Remove the complete setup from its original location. A new verifier
    # process receives only public bundle + explicit public context/message/proof.
    parked = root / "producer-unavailable"
    full.rename(parked)
    verify = ["verify", "--setup", public, "--manifest-sha256", pin,
              "--context", sample / "context.json", "--message", sample / "message.bin",
              "--signature", sample / "signature.bin"]
    verified = call(*verify)
    assert verified["verified"] and verified["vk_sha256"] == generated["vk_sha256"]
    # Public verification is stateless and may be repeated.
    assert call(*verify)["verified"]
    call("sample", "--setup", public, "--manifest-sha256", pin, "--out", root / "no-pk", succeeds=False)

    def reject_mutation(path, change):
        original = path.read_bytes()
        try:
            path.write_bytes(change(original))
            call(*verify, succeeds=False)
        finally:
            path.write_bytes(original)

    reject_mutation(sample / "message.bin", lambda b: b + b"changed")
    reject_mutation(sample / "signature.bin", lambda b: b[:-1])
    reject_mutation(sample / "signature.bin", lambda b: b[:-1] + bytes([b[-1] ^ 1]))
    reject_mutation(sample / "context.json", lambda b: json.dumps({**json.loads(b), "k": 4}).encode())
    for name in ("parameters.bin", "vk.bin", "manifest.json"):
        reject_mutation(public / name, lambda b: b[:-1] + bytes([b[-1] ^ 1]))
    wrong_pin = list(verify)
    wrong_pin[wrong_pin.index("--manifest-sha256") + 1] = "00" * 32
    call(*wrong_pin, succeeds=False)
    # A caller rehashing a changed manifest cannot change the local circuit.
    changed = {**manifest, "circuit": {**manifest["circuit"], "sha256": "00" * 32}}
    original = (public / "manifest.json").read_bytes()
    try:
        encoded = json.dumps(changed).encode()
        (public / "manifest.json").write_bytes(encoded)
        altered = list(verify)
        altered[altered.index("--manifest-sha256") + 1] = hashlib.sha256(encoded).hexdigest()
        call(*altered, succeeds=False)
    finally:
        (public / "manifest.json").write_bytes(original)
    parked.rename(full)

    # New C++-compatible stdio service loads the same bundle rather than calling
    # Setup. Framed setup requests must now report "already completed".
    requests = [{"op": "info"}, {"op": "setup", "capacity": 4},
                {"op": "keygen", "user": "alice", "account": "a"},
                {"op": "join", "account": "a"},
                {"op": "sign", "account": "a", "issue": "01" * 32,
                 "k": 2, "message_b64": "bG9hZGVk", "timestamp": 2}]
    frames = b""
    for request in requests:
        raw = json.dumps(request).encode()
        frames += struct.pack(">I", len(raw)) + raw
    result = subprocess.run([str(executable), "--stdio", "--setup", str(full),
                             "--manifest-sha256", pin], input=frames, capture_output=True,
                            timeout=1200, env=env)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    responses, data = [], result.stdout
    while data:
        assert len(data) >= 4
        n = struct.unpack(">I", data[:4])[0]
        assert len(data) >= n + 4
        responses.append(json.loads(data[4:4+n]))
        data = data[4+n:]
    assert len(responses) == len(requests)
    assert responses[0]["ok"]
    assert not responses[1]["ok"] and "already completed" in responses[1]["error"]
    assert all(r["ok"] for r in responses[2:]) and responses[-1]["signature_b64"]
    result = {"verified": True, "manifest_sha256": pin,
              "vk_sha256": manifest["verifying_key"]["sha256"],
              "checks": "setup/export/load/prove/public-only verify/mutations/stdio reload"}
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--output", type=Path, help="new directory for reproduction artifacts")
    args = parser.parse_args()
    exe = args.executable.resolve()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
        run(exe, args.output.resolve())
    else:
        base = Path(__file__).resolve().parents[1] / "local" / "setup-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="roundtrip-", dir=base) as temp:
            run(exe, Path(temp))


if __name__ == "__main__":
    main()
