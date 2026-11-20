"""Upload size, archive signature, filename sanitization, and UTF-8 limits."""

from __future__ import annotations

import os
import re

_ARCHIVE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"BZh", "BZIP2 archive"),
)

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class UploadLimitError(Exception):
    """Raised when raw upload bytes fail safety intake limits."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def sanitize_filename(filename: str | None) -> str:
    base = os.path.basename((filename or "").replace("\\", "/")).strip()
    cleaned = _SAFE_NAME_RE.sub("_", base).strip("._")
    if not cleaned:
        return "upload"
    return cleaned[:120]


def validate_upload_bytes(raw: bytes, filename: str | None, *, max_bytes: int) -> tuple[str, str]:
    """Validate upload bytes against size, archive, and UTF-8 constraints."""
    safe_name = sanitize_filename(filename)
    if not raw:
        raise UploadLimitError("empty_file", "Uploaded file is empty.")
    if len(raw) > max_bytes:
        raise UploadLimitError(
            "file_too_large",
            f"Upload size {len(raw)} bytes exceeds the maximum allowed {max_bytes} bytes.",
        )
    for sig, label in _ARCHIVE_SIGNATURES:
        if raw.startswith(sig):
            raise UploadLimitError(
                "archive_rejected",
                f"Compressed archive ({label}) uploads are not allowed; upload plain text files.",
            )
    if b"\x00" in raw:
        raise UploadLimitError("binary_rejected", "Binary null bytes are not allowed in imports.")

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UploadLimitError("invalid_encoding", "Import file must be valid UTF-8 text.") from exc
    return safe_name, text
