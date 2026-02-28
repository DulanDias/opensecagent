# OpenSecAgent - PHP malware/backdoor detector (e.g. WordPress, web roots)
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

logger = __import__("logging").getLogger("opensecagent.detector.php_scan")

# Patterns commonly found in PHP backdoors and malware (eval, obfuscation, remote code execution)
PHP_MALWARE_PATTERNS = [
    (r"eval\s*\(\s*base64_decode\s*\(", "eval(base64_decode)", "P1"),
    (r"eval\s*\(\s*gzinflate\s*\(", "eval(gzinflate)", "P1"),
    (r"eval\s*\(\s*gzuncompress\s*\(", "eval(gzuncompress)", "P1"),
    (r"eval\s*\(\s*str_rot13\s*\(", "eval(str_rot13)", "P1"),
    (r"assert\s*\(\s*\$\w+\s*\)", "assert(variable)", "P1"),
    (r"create_function\s*\(", "create_function", "P1"),
    (r"preg_replace\s*\([^)]*\/e\s*[\),]", "preg_replace /e modifier", "P1"),
    (r"shell_exec\s*\(", "shell_exec", "P2"),
    (r"passthru\s*\(", "passthru", "P2"),
    (r"proc_open\s*\(", "proc_open", "P2"),
    (r"pcntl_exec\s*\(", "pcntl_exec", "P2"),
    (r"base64_decode\s*\(\s*[\'\"]\s*[A-Za-z0-9+/=]{20,}", "base64_decode(long string)", "P2"),
    (r"\$\w+\s*\(\s*\$\w+\s*\)\s*;", "variable function call", "P3"),
    (r"file_get_contents\s*\(\s*[\'\"]https?://", "file_get_contents(http)", "P3"),
    (r"curl_exec\s*\(", "curl_exec", "P3"),
    (r"system\s*\(", "system(", "P2"),
    (r"exec\s*\(", "exec(", "P2"),
    (r"popen\s*\(", "popen", "P2"),
]


def _scan_php_files_sync(scan_paths: list[str], max_depth: int, max_files: int, max_bytes: int) -> list[dict[str, Any]]:
    """Find PHP files, check content against malware patterns. Run in executor."""
    events: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for sp in scan_paths:
        p = Path(sp)
        if not p.exists() or not p.is_dir():
            continue
        try:
            for php_file in p.rglob("*.php"):
                if len(seen_paths) >= max_files:
                    break
                try:
                    rel = php_file.relative_to(p)
                    if len(rel.parts) > max_depth:
                        continue
                    if php_file in seen_paths:
                        continue
                    seen_paths.add(php_file)
                    content = php_file.read_bytes()
                    if len(content) > max_bytes:
                        content = content[:max_bytes]
                    text = content.decode("utf-8", errors="ignore")
                    for pattern, name, severity in PHP_MALWARE_PATTERNS:
                        if re.search(pattern, text):
                            events.append({
                                "event_id": f"php-malware-{hash(php_file) % 2**32}",
                                "source": "detector.php_scan",
                                "event_type": "php_malware_suspected",
                                "severity": severity,
                                "summary": f"Suspicious PHP pattern '{name}' in {php_file}",
                                "raw": {
                                    "path": str(php_file),
                                    "pattern": name,
                                    "severity": severity,
                                },
                                "asset_ids": ["host"],
                                "confidence": 0.9,
                            })
                            break
                except (OSError, PermissionError) as e:
                    logger.debug("Cannot read %s: %s", php_file, e)
        except (PermissionError, OSError) as e:
            logger.debug("Cannot scan %s: %s", sp, e)
        if len(seen_paths) >= max_files:
            break
    return events


class PhpScanDetector:
    """Scan PHP files under configured paths for common malware/backdoor patterns (e.g. WordPress)."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        det = config.get("detector", {})
        self._enabled = det.get("php_scan_enabled", True)
        self._scan_paths = det.get("php_scan_paths", ["/var/www", "/home"])
        if isinstance(self._scan_paths, str):
            self._scan_paths = [self._scan_paths]
        self._max_depth = int(det.get("php_scan_max_depth", 8))
        self._max_files = int(det.get("php_scan_max_files", 500))
        self._max_bytes = int(det.get("php_scan_max_bytes", 100 * 1024))

    async def check(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            _scan_php_files_sync,
            self._scan_paths,
            self._max_depth,
            self._max_files,
            self._max_bytes,
        )
