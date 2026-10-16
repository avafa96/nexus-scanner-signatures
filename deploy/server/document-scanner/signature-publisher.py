"""Transfer only official scanner data using a purpose-scoped S3 credential."""

import argparse
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET


def client():
    config = json.loads(os.environ["NEXUS_SCANNER_FEED_CREDENTIAL"])
    assert config["endpoint"] == "https://client.nexusaerosupply.com"
    assert config["bucket"] == "nexus-scanner-signatures"
    return config, dict(os.environ)


def transfer(config, env, source, target, allow_missing=False):
    upload = isinstance(source, pathlib.Path) and str(target).startswith("s3://")
    download = str(source).startswith("s3://") and isinstance(target, pathlib.Path)
    assert upload or download
    address = str(target) if upload else str(source)
    bucket, key = address[5:].split("/", 1)
    assert config["endpoint"] == "https://client.nexusaerosupply.com"
    assert bucket == config["bucket"] == "nexus-scanner-signatures" and key.startswith("official/")
    assert ".." not in key and re.fullmatch(r"[A-Za-z0-9_./-]+", key)
    assert re.fullmatch(r"[A-Za-z0-9_-]{3,128}", config["accessKey"])
    assert re.fullmatch(r"[a-z0-9-]{1,40}", config["region"])
    if upload:
        assert source.is_file() and not source.is_symlink() and source.stat().st_size <= 160_000_000
        with source.open("rb") as data:
            payload = hashlib.file_digest(data, "sha256").hexdigest()
    else:
        assert not target.is_symlink()
        payload = hashlib.sha256(b"").hexdigest()
    method = "PUT" if upload else "GET"
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    scope = day + "/" + config["region"] + "/s3/aws4_request"
    path = "/" + bucket + "/" + key
    signed = "host;x-amz-content-sha256;x-amz-date"
    headers = "host:client.nexusaerosupply.com\nx-amz-content-sha256:" + payload + "\nx-amz-date:" + stamp + "\n"
    canonical = method + "\n" + path + "\n\n" + headers + "\n" + signed + "\n" + payload
    to_sign = "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
    def sign(value, message):
        return hmac.new(value, message.encode(), hashlib.sha256).digest()
    signing_key = sign(sign(sign(sign(("AWS4" + config["secretKey"]).encode(), day), config["region"]), "s3"), "aws4_request")
    signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = "AWS4-HMAC-SHA256 Credential=" + config["accessKey"] + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + signature
    # Auth stays in stdin. Bind the payload; avoid multipart, range concurrency,
    # Expect and trailers. TLS is verified and redirects are never followed.
    curl_config = "header = " + json.dumps("Authorization: " + authorization) + "\n"
    response = pathlib.Path(os.environ["RUNNER_TEMP"]) / "scanner-feed-transfer-response.xml" if upload else target
    clean_env = {k: v for k, v in env.items() if k not in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "NEXUS_SCANNER_FEED_CREDENTIAL"}}
    command = ["curl", "--config", "-", "--silent", "--show-error", "--http1.1",
               "--connect-timeout", "15", "--max-time", "720", "--request", method,
               "--header", "Expect:", "--header", "x-amz-content-sha256: " + payload,
               "--header", "x-amz-date: " + stamp, "--output", str(response),
               "--write-out", "%{http_code}", "--url", config["endpoint"] + path]
    if upload:
        command += ["--upload-file", str(source)]
    result = subprocess.run(command, env=clean_env, input=curl_config, capture_output=True, text=True, timeout=750)
    status = int(result.stdout) if re.fullmatch(r"[0-9]{3}", result.stdout) else 0
    if result.returncode != 0 or status != 200:
        label = "HTTP_ERROR"
        if response.is_file() and response.stat().st_size <= 65536:
            try:
                code = ET.fromstring(response.read_text()).findtext("Code", "")
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,63}", code):
                    label = code
            except (ET.ParseError, UnicodeDecodeError):
                pass
        if download and allow_missing and result.returncode == 0 and status == 404 and label == "NoSuchKey":
            return False
        raise RuntimeError("Scoped scanner transfer failed (" + label + ", http=" + str(status) + ", transport=" + str(result.returncode) + "); protected output suppressed")
    if download:
        assert response.is_file() and not response.is_symlink() and response.stat().st_size <= 160_000_000
    return True


CHUNK_BYTES = 8 * 1024 * 1024
TRANSFER_SCHEMA = "NEXUS_OFFICIAL_SCANNER_CHUNKS_V1"


def store_chunks(config, env, archive, category):
    run = os.environ["GITHUB_RUN_ID"]
    assert re.fullmatch(r"[0-9]{1,24}", run) and category in {"packet", "state"}
    size = archive.stat().st_size
    assert 0 < size <= 160_000_000 and not archive.is_symlink()
    with archive.open("rb") as data:
        digest = hashlib.file_digest(data, "sha256").hexdigest()
    parts = []
    with tempfile.TemporaryDirectory(prefix="scanner-chunks-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        chunk = pathlib.Path(temporary) / "part.bin"
        with archive.open("rb") as data:
            while block := data.read(CHUNK_BYTES):
                key = "official/chunks/" + run + "/" + category + "/" + digest + "/" + f"{len(parts):03d}" + ".part"
                chunk.write_bytes(block)
                transfer(config, env, chunk, "s3://nexus-scanner-signatures/" + key)
                parts.append({"key": key, "bytes": len(block), "sha256": hashlib.sha256(block).hexdigest()})
    with archive.open("rb") as data:
        assert digest == hashlib.file_digest(data, "sha256").hexdigest()
    assert size == sum(part["bytes"] for part in parts) and 1 <= len(parts) <= 20
    return {"transferSchema": TRANSFER_SCHEMA, "transferRunId": run, "archiveBytes": size, "archiveSha256": digest, "chunks": parts}


def restore_chunks(config, env, descriptor, target, category):
    assert descriptor["transferSchema"] == TRANSFER_SCHEMA and category in {"packet", "state"}
    run, parts = descriptor["transferRunId"], descriptor["chunks"]
    assert isinstance(run, str) and re.fullmatch(r"[0-9]{1,24}", run)
    assert isinstance(parts, list) and 1 <= len(parts) <= 20
    assert isinstance(descriptor["archiveBytes"], int) and 0 < descriptor["archiveBytes"] <= 160_000_000
    assert re.fullmatch(r"[0-9a-f]{64}", descriptor["archiveSha256"])
    for index, part in enumerate(parts):
        assert part["key"] == "official/chunks/" + run + "/" + category + "/" + descriptor["archiveSha256"] + "/" + f"{index:03d}" + ".part"
        assert isinstance(part["bytes"], int) and 0 < part["bytes"] <= CHUNK_BYTES
        assert re.fullmatch(r"[0-9a-f]{64}", part["sha256"])
    assert sum(part["bytes"] for part in parts) == descriptor["archiveBytes"]
    assert not target.is_symlink()
    with tempfile.TemporaryDirectory(prefix="scanner-restore-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        chunk = pathlib.Path(temporary) / "part.bin"
        with target.open("wb") as output:
            for part in parts:
                transfer(config, env, "s3://nexus-scanner-signatures/" + part["key"], chunk)
                assert chunk.stat().st_size == part["bytes"]
                with chunk.open("rb") as data:
                    assert hashlib.file_digest(data, "sha256").hexdigest() == part["sha256"]
                output.write(chunk.read_bytes())
    assert target.stat().st_size == descriptor["archiveBytes"]
    with target.open("rb") as data:
        assert hashlib.file_digest(data, "sha256").hexdigest() == descriptor["archiveSha256"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["restore", "state", "publish"])
    args = parser.parse_args()
    config, env = client()
    packet = pathlib.Path(os.environ["RUNNER_TEMP"]) / "clamav-packet"
    database = packet / "databases"
    database.mkdir(parents=True, exist_ok=True)
    state = packet / "freshclam-state.tar.gz"
    state_url = "s3://nexus-scanner-signatures/official/freshclam-state.tar.gz"
    if args.mode == "restore":
        descriptor = packet / "freshclam-state-pointer.json"
        if transfer(config, env, "s3://nexus-scanner-signatures/official/freshclam-state.json", descriptor, allow_missing=True):
            assert descriptor.stat().st_size <= 32768
            restore_chunks(config, env, json.loads(descriptor.read_text()), state, "state")
        elif not transfer(config, env, state_url, state, allow_missing=True):
            print("No prior official updater state; initialize once")
            return
        with tarfile.open(state, "r:gz") as tar:
            members = tar.getmembers()
            assert len(members) <= 12 and sum(m.size for m in members) <= 160_000_000
            assert len({m.name for m in members}) == len(members)
            for member in members:
                assert member.isfile() and "/" not in member.name and "\\" not in member.name
                assert member.name in {"main.cvd", "daily.cvd", "bytecode.cvd", "freshclam.dat"} or (
                    member.name.endswith(".cvd.sign")
                    and member.name.split("-")[0] in {"main", "daily", "bytecode"}
                )
            tar.extractall(database, members=members, filter="data")
        print("Restored persistent official updater state, including cooldown")
    elif args.mode == "state":
        if not (packet / "update.log").is_file():
            return
        paths = [database / "freshclam.dat"]
        for name in ["main", "daily", "bytecode"]:
            cvd = database / (name + ".cvd")
            if cvd.is_file():
                with cvd.open("rb") as data:
                    version = int(data.read(512).decode("ascii").split(":")[2])
                paths.extend([cvd, database / (name + "-" + str(version) + ".cvd.sign")])
        with tarfile.open(state, "w:gz") as tar:
            for path in paths:
                if path.is_file():
                    assert not path.is_symlink()
                    tar.add(path, arcname=path.name)
        descriptor = packet / "freshclam-state-pointer.json"
        descriptor.write_text(json.dumps(store_chunks(config, env, state, "state")) + "\n")
        transfer(config, env, descriptor, "s3://nexus-scanner-signatures/official/freshclam-state.json")
        print("Preserved official updater databases and cooldown state")
    else:
        archive = pathlib.Path(os.environ["RUNNER_TEMP"]) / "clamav-official-signatures.tar.gz"
        manifest = json.loads((packet / "manifest.json").read_text())
        assert manifest["sourceCommit"] == os.environ["GITHUB_SHA"]
        assert manifest["runId"] == os.environ["GITHUB_RUN_ID"] and manifest["runId"].isdigit()
        for check in ["cryptographicVerification", "engineLoadTest", "cleanEngineCheck", "infectedEngineCheck"]:
            assert manifest[check] == "PASSED"
        with archive.open("rb") as data:
            digest = hashlib.file_digest(data, "sha256").hexdigest()
        key = "official/packets/" + manifest["runId"] + ".tar.gz"
        descriptor = store_chunks(config, env, archive, "packet")
        assert descriptor["archiveSha256"] == digest
        pointer = packet / "current.json"
        pointer.write_text(json.dumps({**descriptor, "archiveKey": key, "manifest": manifest}) + "\n")
        # Commit the pointer last; a reader always gets a complete immutable packet.
        transfer(config, env, pointer, "s3://nexus-scanner-signatures/official/current.json")
        print(json.dumps({"status": "VERIFIED_OFFICIAL_PACKET_PUBLISHED", "runId": manifest["runId"], "dailyVersion": manifest["dailyVersion"], "archiveSha256": digest}))


if __name__ == "__main__":
    main()
