#!/usr/bin/env python3
"""Recheck exported demo evidence using a separately built native verifier."""
import argparse
import json
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", required=True, type=pathlib.Path)
    args = parser.parse_args()
    verifier = args.verifier.resolve(strict=True)
    root = pathlib.Path(__file__).resolve().parent
    reports = sorted((root / "reports").iterdir())
    if len(reports) != 6:
        raise SystemExit("Expected the six-report demo bundle")

    def command(report):
        return [str(verifier), "verify-authorized", "--setup", str(root / "public-setup"),
                "--policy", str(report / "policy.json"), "--setup-approval", str(root / "setup-approval.json"),
                "--registry", str(report / "registry.json"), "--message", str(report / "message.json"),
                "--signature", str(report / "signature.bin")]

    for report in reports:
        result = subprocess.run(command(report), capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise SystemExit(f"Report {report.name} failed: {result.stderr}")
        if json.loads(result.stdout).get("verified") is not True:
            raise SystemExit(f"Report {report.name} did not return verified=true")
        print(f"PASS signature {report.name} (not a business acceptance decision)")

    for flag, replacement, diagnostic in [
        ("--message", "tampered-message.json", "message mismatch"),
        ("--policy", "current-policy.json", "registry authority scope, epoch, policy or validity mismatch"),
    ]:
        cmd = command(reports[0])
        cmd[cmd.index(flag) + 1] = str(root / replacement)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 1 or result.stderr.strip() != diagnostic:
            raise SystemExit(f"Expected {diagnostic!r} for {replacement}: {result.stdout} {result.stderr}")
        print(f"PASS rejected {replacement}")
    print("Six public proofs and two negative checks passed.")


if __name__ == "__main__":
    main()
