#!/usr/bin/env python3
"""Temporarily test one camera's cloud endpoint through a Proxmox guest agent.

Uses the existing RTSP consumer. It never reads credentials or creates another
camera session. The original source is restored and verified before exit.
"""

import argparse
import collections
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time
import urllib.request

CAMERAS = ("Kuna_Front_Door", "Kuna_Basement_Door", "Kuna_Deck_Door")
BASELINE_SECONDS = 60
WARMUP_SECONDS = 60
INTERVAL_SECONDS = 15
URL = "wss://video.kunasystems.com/ws/rtsp/proxy?authtoken="
TRIAL_ANCHOR = b'        self.camera = camera\n        self.port = port\n'


def guest(args, command, timeout=70):
    result = subprocess.run(["sudo", "-n", "qm", "guest", "exec", str(args.vmid),
                             "--", "/bin/sh", "-c", command], capture_output=True,
                            text=True, timeout=timeout, check=True)
    envelope = json.loads(result.stdout)
    if not envelope.get("exited") or envelope.get("exitcode") != 0:
        # Never forward arbitrary guest output; it could include credentials.
        raise RuntimeError("guest command failed; exit=" + str(envelope.get("exitcode")))
    if envelope.get("out-truncated") or envelope.get("err-truncated"):
        raise RuntimeError("guest output was truncated")
    return envelope.get("out-data", "")


def python_in_bridge(args, program):
    return guest(args, shlex.join(["docker", "exec", args.container, "python3", "-c", program]))


def source_hash(args):
    return guest(args, shlex.join(["docker", "exec", args.container, "sha256sum", "/app/kuna_server.py"])).split()[0]


def restart(args):
    guest(args, shlex.join(["docker", "restart", "--time", "20", args.container]))


def identity(args):
    value = guest(args, shlex.join(["docker", "inspect", "--format", "{{.Id}} {{.Image}} {{.State.StartedAt}}", args.container]))
    container_id, image, started = value.split()
    return {"container_id": container_id, "image": image, "started": started}


def camera_map(args, since):
    logs = guest(args, shlex.join(["docker", "logs", "--since", since, "--tail", "20000", args.container]) + " 2>&1")
    pattern = r'Client: start listening for camera: (\S+) \(([^)]+)\) on [^:]+:(\d+)'
    return {port: {"id": camera, "name": name} for camera, name, port in re.findall(pattern, logs)}


def verify_mapping(args, expected, started):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        current = camera_map(args, started)
        if current:
            if current != expected:
                raise RuntimeError("camera-to-port mapping changed during trial")
            return
        time.sleep(2)
    raise RuntimeError("could not verify restarted camera-to-port mapping")


def exit_through_cleanup(signum, frame):
    raise KeyboardInterrupt(f"trial interrupted by signal {signum}")


def frame_sample(args):
    with urllib.request.urlopen(args.stats_url, timeout=6) as response:
        stats = json.load(response)
    timestamp = stats["service"]["last_updated"]
    if time.time() - timestamp > 90 or timestamp > time.time() + 5:
        raise ValueError("stale Frigate stats")
    keys = ("camera_fps", "expected_fps", "process_fps", "skipped_fps", "detection_fps")
    return {"time": time.time(), "sample_time": timestamp,
            "cameras": {name: {key: stats["cameras"][name].get(key) for key in keys} for name in CAMERAS}}


def log_counts(args, since):
    # Return aggregates only, not authenticated URLs, camera serials or raw logs.
    command = shlex.join(["docker", "logs", "--since", str(since), "--tail", "20000", args.container])
    logs = guest(args, command + " 2>&1")
    counts = collections.defaultdict(collections.Counter)
    for line in logs.splitlines():
        match = re.search(r'KunaWS\[[^]]*\]\[([^]]*)\]', line)
        if not match:
            continue
        camera = match[1]
        if 'Error ID' in line and 'Connection refused' in line:
            counts[camera]['connection_refused'] += 1
        if 'SSLCertVerificationError' in line:
            counts[camera]['tls_failure'] += 1
        if 'Timed out waiting for Kuna channel setup' in line:
            counts[camera]['setup_timeout'] += 1
    return dict(counts)


def observe(args, duration, phase, report):
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            sample = frame_sample(args)
            sample["phase"] = phase
            report["samples"].append(sample)
            rates = " ".join(f"{name}={value['camera_fps']}/{value['process_fps']}" for name, value in sample["cameras"].items())
            print(f"{phase}: {rates}", flush=True)
        except (OSError, ValueError, KeyError) as error:
            report["samples"].append({"phase": phase, "time": time.time(), "error": type(error).__name__})
            print(f"{phase}: stats unavailable ({type(error).__name__})", flush=True)
        time.sleep(min(INTERVAL_SECONDS, max(0, deadline - time.monotonic())))


def install_trial(args, expected, backup):
    program = f'''
from pathlib import Path
import hashlib, os
path = Path('/app/kuna_server.py')
backup = Path({backup!r})
source = path.read_bytes()
assert hashlib.sha256(source).hexdigest() == {expected!r}, 'source changed'
anchor = {TRIAL_ANCHOR!r}
assert source.count(anchor) == 1, 'ambiguous trial anchor'
replacement = anchor + {f'        if port == {args.port}:\n            self.ws_url = {URL!r}\n'.encode()!r}
candidate = source.replace(anchor, replacement, 1)
compile(candidate, str(path), 'exec')
with backup.open('xb') as stream:
    stream.write(source)
os.chmod(backup, 0o600)
temporary = path.with_suffix('.trial')
temporary.write_bytes(candidate)
os.chmod(temporary, 0o644)
temporary.replace(path)
print(hashlib.sha256(candidate).hexdigest())
'''
    return python_in_bridge(args, program).strip()


def restore(args, expected, candidate_hash, backup):
    program = f'''
from pathlib import Path
import hashlib, os
path = Path('/app/kuna_server.py')
backup = Path({backup!r})
source = backup.read_bytes()
assert hashlib.sha256(source).hexdigest() == {expected!r}, 'backup changed'
current = hashlib.sha256(path.read_bytes()).hexdigest()
assert current in ({expected!r}, {candidate_hash!r}), 'concurrent source change; refusing overwrite'
temporary = path.with_suffix('.restore')
temporary.write_bytes(source)
os.chmod(temporary, 0o644)
temporary.replace(path)
print(hashlib.sha256(path.read_bytes()).hexdigest())
'''
    restored = python_in_bridge(args, program).strip()
    if restored != expected:
        raise RuntimeError("restore hash mismatch")
    restart(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vmid", type=int, default=101)
    parser.add_argument("--container", default="app_bedb4ecd_kuna_server")
    parser.add_argument("--port", type=int, default=4555)
    parser.add_argument("--stats-url", default="http://127.0.0.1:5005/api/stats")
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--expected-image", help="Require this exact running image ID")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, exit_through_cleanup)
    if not 120 <= args.seconds <= 900 or not 1 <= args.port <= 65535:
        parser.error("trial duration must be 120..900 seconds and port must be valid")
    initial = identity(args)
    if args.expected_image and initial["image"] != args.expected_image:
        raise RuntimeError("unexpected running image")
    # Bind every later operation to this ID, not a mutable container name.
    args.container = initial["container_id"]
    mapping = camera_map(args, initial["started"])
    if str(args.port) not in mapping or len(mapping) != 3:
        raise RuntimeError("could not establish the three-camera port mapping")
    expected = hashlib.sha256((Path(__file__).parents[1] / "homeassistant-addon/kuna_server.py").read_bytes()).hexdigest()
    if source_hash(args) != expected:
        raise RuntimeError("deployed bridge does not match the checked-out source")
    report = {"started": datetime.now(timezone.utc).isoformat(), "original_sha256": expected,
              "port": args.port, "endpoint": URL, "samples": [], "restored": False,
              "identity": initial, "mapping": mapping}
    baseline_start = int(time.time())
    observe(args, BASELINE_SECONDS, "baseline", report)
    report["baseline_errors"] = log_counts(args, baseline_start)
    backup = f"/data/kuna-server-before-endpoint-trial-{int(time.time())}.py"
    report["backup"] = backup
    trial_hash = None
    try:
        trial_hash = install_trial(args, expected, backup)
        report["trial_sha256"] = trial_hash
        print("Basement-only trial source installed; restarting the bridge", flush=True)
        restart(args)
        restarted = identity(args)
        if restarted["image"] != initial["image"]:
            raise RuntimeError("image changed during trial restart")
        verify_mapping(args, mapping, restarted["started"])
        observe(args, WARMUP_SECONDS, "warmup", report)
        trial_start = int(time.time())
        observe(args, args.seconds, "trial", report)
        report["trial_errors"] = log_counts(args, trial_start)
    finally:
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(signum, signal.SIG_IGN)
        # If an application call timed out after writing, still attempt recovery
        # using a deterministic candidate hash rather than trusting its response.
        if trial_hash is None:
            original = (Path(__file__).parents[1] / "homeassistant-addon/kuna_server.py").read_bytes()
            anchor = TRIAL_ANCHOR
            replacement = anchor + f'        if port == {args.port}:\n            self.ws_url = {URL!r}\n'.encode()
            trial_hash = hashlib.sha256(original.replace(anchor, replacement, 1)).hexdigest()
        try:
            restore(args, expected, trial_hash, backup)
            restored = identity(args)
            if restored["image"] != initial["image"]:
                raise RuntimeError("image changed during restore")
            verify_mapping(args, mapping, restored["started"])
            report["restored"] = True
            print("Original bridge source restored and restarted", flush=True)
        finally:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2))
            args.output.chmod(0o600)
    print("Trial evidence: " + str(args.output), flush=True)


if __name__ == "__main__":
    main()
