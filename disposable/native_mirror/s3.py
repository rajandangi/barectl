"""A tiny S3-compatible server for the offline native lane (Phase D #403).

The backups scenarios copy a site's repository to offsite storage. Reaching Amazon S3 or
Cloudflare R2 needs the internet, which the native lane forbids, so this fixture answers the
small part of the S3 API restic's S3 backend uses: bucket existence and creation, object
put/get/head/delete, ListObjectsV2, and multipart upload. It keeps every object as a file
under the bucket directory, so the scenario can also inspect the bucket directly.

It is a test fixture, not a product backend. It ignores signatures, which is safe because it
listens only on a scenario server's loopback address for the length of one test.
"""

import argparse
import base64
import hashlib
import os
import re
import shutil
import ssl
import sys
import threading
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from datetime import UTC, datetime
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast, override
from urllib.parse import parse_qs, quote, unquote, urlsplit

NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"
MAX_KEY = 1024


def _xml(root: ET.Element) -> bytes:
    return bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))


def _element(parent: ET.Element, name: str, text: object) -> None:
    child = ET.SubElement(parent, name)
    child.text = str(text)


def _timestamp(value: float) -> str:
    """ListObjectsV2 answers LastModified in ISO 8601, not the HTTP date form."""
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def error_body(code: str, message: str) -> bytes:
    root = ET.Element("Error")
    _element(root, "Code", code)
    _element(root, "Message", message)
    return _xml(root)


class Store:
    """The bucket and object files under one root directory."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.lock = threading.Lock()
        (root / ".uploads").mkdir(parents=True, exist_ok=True)

    def bucket(self, name: str) -> Path:
        return self.root / name

    def object(self, bucket: str, key: str) -> Path:
        return self.bucket(bucket) / key

    def safe_key(self, key: str) -> bool:
        return (
            bool(key)
            and len(key) <= MAX_KEY
            and not key.startswith("/")
            and all(part not in ("", ".", "..") for part in key.split("/"))
            and "\0" not in key
        )

    def entries(self, bucket: str, prefix: str) -> list[tuple[str, Path]]:
        base = self.bucket(bucket)
        if not base.is_dir():
            return []
        found: list[tuple[str, Path]] = []
        for directory, _children, files in os.walk(base):
            if Path(directory) == self.root / ".uploads":
                continue
            for name in files:
                path = Path(directory) / name
                key = path.relative_to(base).as_posix()
                if key.startswith(prefix) and not key.startswith(".uploads/"):
                    found.append((key, path))
        return sorted(found)

    def upload(self, upload_id: str) -> Path:
        return self.root / ".uploads" / upload_id


class Handler(BaseHTTPRequestHandler):
    server_version = "BarectlS3Fixture/1"

    @property
    def store(self) -> Store:
        return cast("S3Server", self.server).store

    @override
    def log_message(self, message: str, *args: object) -> None:
        sys.stderr.write("s3: " + (message % args) + "\n")

    def _split(self) -> tuple[str, str, dict[str, list[str]]]:
        parsed = urlsplit(self.path)
        parts = parsed.path.lstrip("/").split("/", 1)
        bucket = unquote(parts[0]) if parts and parts[0] else ""
        key = unquote(parts[1]) if len(parts) > 1 else ""
        return bucket, key, parse_qs(parsed.query, keep_blank_values=True)

    def _send(
        self,
        status: int,
        body: bytes = b"",
        *,
        content_type: str = "application/xml",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        supplied = headers or {}
        if "Content-Length" not in supplied:
            self.send_header("Content-Length", str(len(body)))
        for name, value in supplied.items():
            self.send_header(name, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, status: int, code: str, message: str) -> None:
        self._send(status, error_body(code, message))

    def _body(self) -> bytes:
        length = self.headers.get("Content-Length")
        data = b""
        if length is not None:
            data = self.rfile.read(int(length))
        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = self._chunked()
        # minio-go signs streamed uploads as aws-chunked: each chunk carries its own
        # signature line around the plain bytes.
        if (
            self.headers.get("Content-Encoding", "").lower() == "aws-chunked"
            or self.headers.get("x-amz-decoded-content-length") is not None
        ):
            return self._decode_aws_chunks(data)
        return data

    def _decode_aws_chunks(self, data: bytes) -> bytes:
        output = bytearray()
        offset = 0
        while offset < len(data):
            end = data.find(b"\r\n", offset)
            if end < 0:
                break
            header = data[offset:end].split(b";", 1)[0]
            try:
                size = int(header, 16)
            except ValueError:
                break
            if size == 0:
                break
            start = end + 2
            output.extend(data[start : start + size])
            offset = start + size + 2
        return bytes(output)

    def _chunked(self) -> bytes:
        parts: list[bytes] = []
        while True:
            line = self.rfile.readline(128).strip()
            if not line:
                break
            size = int(line.split(b";", 1)[0], 16)
            if size == 0:
                self.rfile.readline(128)
                break
            parts.append(self.rfile.read(size))
            self.rfile.read(2)
        return b"".join(parts)

    def _md5(self, path: Path) -> str:
        digest = hashlib.md5(usedforsecurity=False)
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        return '"' + digest.hexdigest() + '"'

    def do_HEAD(self) -> None:
        bucket, key, _query = self._split()
        if not self.store.bucket(bucket).is_dir():
            self._error(404, "NoSuchBucket", "The bucket does not exist.")
            return
        if not key:
            self._send(200)
            return
        path = self.store.object(bucket, key)
        if not self.store.safe_key(key) or not path.is_file():
            self._error(404, "NoSuchKey", "The object does not exist.")
            return
        self._send(
            200,
            headers={
                "Content-Length": str(path.stat().st_size),
                "ETag": self._md5(path),
                "Last-Modified": formatdate(path.stat().st_mtime, usegmt=True),
                "Accept-Ranges": "bytes",
            },
        )

    def do_DELETE(self) -> None:
        bucket, key, query = self._split()
        if "uploadId" in query:
            with self.store.lock:
                shutil.rmtree(self.store.upload(query["uploadId"][0]), ignore_errors=True)
            self._send(204)
            return
        if not key:
            with self.store.lock:
                shutil.rmtree(self.store.bucket(bucket), ignore_errors=True)
            self._send(204)
            return
        path = self.store.object(bucket, key)
        with self.store.lock:
            path.unlink(missing_ok=True)
        self._send(204)

    def do_PUT(self) -> None:
        bucket, key, query = self._split()
        if not key:
            with self.store.lock:
                self.store.bucket(bucket).mkdir(parents=True, exist_ok=True)
            self._send(200)
            return
        if "partNumber" in query and "uploadId" in query:
            self._put_part(query["uploadId"][0], int(query["partNumber"][0]))
            return
        if not self.store.safe_key(key) or not self.store.bucket(bucket).is_dir():
            self._error(404, "NoSuchBucket", "The bucket does not exist.")
            return
        body = self._body()
        path = self.store.object(bucket, key)
        with self.store.lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".part")
            temporary.write_bytes(body)
            os.replace(temporary, path)
        self._send(200, headers={"ETag": self._md5(path)})

    def _put_part(self, upload_id: str, number: int) -> None:
        body = self._body()
        directory = self.store.upload(upload_id)
        directory.mkdir(parents=True, exist_ok=True)
        part = directory / f"part-{number:05d}"
        part.write_bytes(body)
        digest = hashlib.md5(body, usedforsecurity=False).hexdigest()
        self._send(200, headers={"ETag": '"' + digest + '"'})

    def do_GET(self) -> None:
        bucket, key, query = self._split()
        if not bucket:
            self._error(400, "InvalidRequest", "A bucket is required.")
            return
        if not self.store.bucket(bucket).is_dir():
            self._error(404, "NoSuchBucket", "The bucket does not exist.")
            return
        if not key:
            if "location" in query:
                root = ET.Element("LocationConstraint")
                root.text = "us-east-1"
                self._send(200, _xml(root))
                return
            self._list(bucket, query)
            return
        path = self.store.object(bucket, key)
        if not self.store.safe_key(key) or not path.is_file():
            self._error(404, "NoSuchKey", "The object does not exist.")
            return
        data = path.read_bytes()
        self._send(
            200,
            data,
            content_type="application/octet-stream",
            headers={
                "ETag": self._md5(path),
                "Last-Modified": formatdate(path.stat().st_mtime, usegmt=True),
            },
        )

    def _list(self, bucket: str, query: dict[str, list[str]]) -> None:
        prefix = query.get("prefix", [""])[0]
        max_keys = min(int(query.get("max-keys", ["1000"])[0] or 1000), 1000)
        token = query.get("continuation-token", [""])[0]
        start = 0
        if token:
            try:
                start = int(base64.urlsafe_b64decode(token.encode()).decode())
            except ValueError:
                start = 0
        entries = self.store.entries(bucket, prefix)
        page = entries[start : start + max_keys]
        truncated = start + max_keys < len(entries)
        root = ET.Element("ListBucketResult", xmlns=NAMESPACE)
        _element(root, "Name", bucket)
        _element(root, "Prefix", prefix)
        _element(root, "KeyCount", len(page))
        _element(root, "MaxKeys", max_keys)
        _element(root, "IsTruncated", "true" if truncated else "false")
        if truncated:
            token = base64.urlsafe_b64encode(str(start + max_keys).encode()).decode()
            _element(root, "NextContinuationToken", token)
        for name, path in page:
            item = ET.SubElement(root, "Contents")
            _element(item, "Key", quote(name, safe="/"))
            _element(item, "LastModified", _timestamp(path.stat().st_mtime))
            _element(item, "ETag", self._md5(path))
            _element(item, "Size", path.stat().st_size)
            _element(item, "StorageClass", "STANDARD")
        self._send(200, _xml(root))

    def do_POST(self) -> None:
        bucket, key, query = self._split()
        if "uploads" in query:
            upload_id = uuid.uuid4().hex
            self.store.upload(upload_id).mkdir(parents=True, exist_ok=True)
            root = ET.Element("InitiateMultipartUploadResult", xmlns=NAMESPACE)
            _element(root, "Bucket", bucket)
            _element(root, "Key", key)
            _element(root, "UploadId", upload_id)
            self._send(200, _xml(root))
            return
        if "uploadId" in query:
            self._complete(bucket, key, query["uploadId"][0])
            return
        self._error(400, "InvalidRequest", "Unsupported request.")

    def _complete(self, bucket: str, key: str, upload_id: str) -> None:
        body = self._body()
        numbers: list[int] = []
        try:
            root = ET.fromstring(body) if body else None  # noqa: S314 - the lane's own upload
        except ET.ParseError:
            root = None
        if root is not None:
            for element in root:
                for child in element:
                    if child.tag.rsplit("}", 1)[-1] == "PartNumber" and child.text:
                        numbers.extend([int(child.text)])
        directory = self.store.upload(upload_id)
        files = sorted(directory.glob("part-*")) if directory.is_dir() else []
        if numbers:
            files = [directory / f"part-{number:05d}" for number in numbers]
        path = self.store.object(bucket, key)
        with self.store.lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".part")
            with temporary.open("wb") as handle:
                for portion in files:
                    if portion.is_file():
                        handle.write(portion.read_bytes())
            os.replace(temporary, path)
            shutil.rmtree(directory, ignore_errors=True)
        result = ET.Element("CompleteMultipartUploadResult", xmlns=NAMESPACE)
        _element(result, "Location", f"/{bucket}/{key}")
        _element(result, "Bucket", bucket)
        _element(result, "Key", key)
        _element(result, "ETag", self._md5(path))
        self._send(200, _xml(result))


class S3Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self, address: tuple[str, int], store: Store, context: ssl.SSLContext | None
    ) -> None:
        super().__init__(address, Handler)
        self.store = store
        if context is not None:
            self.socket = context.wrap_socket(self.socket, server_side=True)


def split_address(value: str) -> tuple[str, int]:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        raise argparse.ArgumentTypeError("not an address")
    host, separator, port = value.rpartition(":")
    if not separator:
        return value, 443
    return host or "0.0.0.0", int(port)  # noqa: S104 - the scenario server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--address", default="0.0.0.0:443", type=split_address)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--key", type=Path)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    context = None
    if options.certificate is not None and options.key is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(options.certificate, options.key)
    server = S3Server(options.address, Store(options.root), context)
    sys.stderr.write(f"s3: serving {options.root} on {options.address[0]}:{options.address[1]}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
