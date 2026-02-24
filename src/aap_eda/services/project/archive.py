#  Copyright 2024 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Archive download and extraction for Remote Archive SCM projects."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from typing import Optional
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from aap_eda.core.types import StrPath

logger = logging.getLogger(__name__)

# Max download size: 500MB
MAX_ARCHIVE_DOWNLOAD_SIZE = 500 * 1024 * 1024


class ArchiveError(Exception):
    pass


def download_and_extract(
    url: str,
    dest: StrPath,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
) -> str:
    """Download an archive from URL, extract to dest, return SHA1 checksum.

    Returns the SHA1 hex digest of the downloaded archive, used as
    the revision identifier (matching AWX Controller's checksum_src).

    Raises ArchiveError on failure.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ArchiveError(f"Unsupported archive URL scheme: {parsed.scheme}")

    with tempfile.NamedTemporaryFile(
        suffix=_suffix_from_url(url), delete=False
    ) as tmp:
        tmp_path = tmp.name
        try:
            _download_file(
                url,
                tmp_path,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
                proxy=proxy,
            )
            checksum = _sha1_file(tmp_path)
            _extract_archive(tmp_path, dest)
        finally:
            os.unlink(tmp_path)

    return checksum


def _suffix_from_url(url: str) -> str:
    path = urlparse(url).path.lower()
    if path.endswith(".tar.gz") or path.endswith(".tgz"):
        return ".tar.gz"
    if path.endswith(".tar.bz2"):
        return ".tar.bz2"
    if path.endswith(".tar"):
        return ".tar"
    if path.endswith(".zip"):
        return ".zip"
    return ""


def _download_file(
    url: str,
    dest: str,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
) -> None:
    import ssl

    request = Request(url)

    if username and password:
        import base64

        cred_str = f"{username}:{password}"  # noqa: E231
        credentials = base64.b64encode(cred_str.encode()).decode()
        request.add_header("Authorization", f"Basic {credentials}")
    elif password:
        request.add_header("Authorization", f"Bearer {password}")

    context = None
    if not verify_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    # Proxy support via environment is handled by urllib
    # automatically when http_proxy/https_proxy are set.
    # For explicit proxy, we set env vars temporarily.
    old_env = {}
    if proxy:
        for key in ("http_proxy", "https_proxy"):
            old_env[key] = os.environ.get(key)
            os.environ[key] = proxy

    try:
        with urlopen(request, context=context, timeout=300) as response:
            total = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARCHIVE_DOWNLOAD_SIZE:
                        raise ArchiveError(
                            "Archive exceeds maximum download"
                            f" size ({MAX_ARCHIVE_DOWNLOAD_SIZE}"
                            " bytes)"
                        )
                    f.write(chunk)
    except URLError as e:
        raise ArchiveError(f"Failed to download archive: {e}") from e
    finally:
        if proxy:
            for key, val in old_env.items():
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val


def _sha1_file(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _extract_archive(archive_path: str, dest: str) -> None:
    """Extract archive with zip-slip protection and root-dir skipping."""
    if zipfile.is_zipfile(archive_path):
        _extract_zip(archive_path, dest)
    elif tarfile.is_tarfile(archive_path):
        _extract_tar(archive_path, dest)
    else:
        raise ArchiveError(
            "Unsupported archive format. "
            "Expected .zip, .tar, .tar.gz, or .tar.bz2"
        )


def _find_root_dir(names: list[str]) -> Optional[str]:
    """Detect single root directory in archive (common pattern).

    If all files share a common top-level directory prefix,
    return it so we can skip it during extraction (matching
    AWX Controller's root-dir skipping behavior).
    """
    if not names:
        return None
    tops = set()
    for name in names:
        parts = name.split("/", 1)
        tops.add(parts[0])
    if len(tops) == 1:
        root = tops.pop()
        if root:
            return root
    return None


def _safe_path(dest: str, member_path: str) -> str:
    """Validate extracted path against zip-slip attacks."""
    target = os.path.realpath(os.path.join(dest, member_path))
    if not target.startswith(os.path.realpath(dest) + os.sep):
        if target != os.path.realpath(dest):
            raise ArchiveError(f"Zip-slip detected: {member_path}")
    return target


def _extract_zip(archive_path: str, dest: str) -> None:
    with zipfile.ZipFile(archive_path, "r") as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        root = _find_root_dir(zf.namelist())
        for member in names:
            rel = member
            if root and rel.startswith(root + "/"):
                rel = rel[len(root) + 1 :]
            if not rel:
                continue
            target = _safe_path(dest, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)


def _extract_tar(archive_path: str, dest: str) -> None:
    with tarfile.open(archive_path, "r:*") as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        names = [m.name for m in tf.getmembers()]
        root = _find_root_dir(names)
        for member in members:
            rel = member.name
            if root and rel.startswith(root + "/"):
                rel = rel[len(root) + 1 :]
            if not rel:
                continue
            target = _safe_path(dest, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tf.extractfile(member) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
