"""
SecAudit 2.0 - Pattern & Ignore Matcher
Handles custom .sppsignore and default exclusions.
"""

import os
import fnmatch
from typing import List
from .config import IGNORE_DIRS


class IgnoreMatcher:
    """
    Parses .sppsignore file located in target directory and provides path filtering.
    """

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir) if target_dir else ""
        self.patterns: List[str] = []
        self._load_ignore_file()

    def _load_ignore_file(self):
        if not self.target_dir or not os.path.isdir(self.target_dir):
            return

        ignore_file = os.path.join(self.target_dir, ".sppsignore")
        if os.path.isfile(ignore_file):
            try:
                with open(ignore_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        norm = line.replace("\\", "/")
                        self.patterns.append(norm)
            except Exception:
                pass

    def is_ignored(self, path: str, is_dir: bool = False) -> bool:
        if not self.target_dir:
            return False

        rel_path = os.path.relpath(path, self.target_dir).replace("\\", "/")
        name = os.path.basename(path)
        rel_segments = rel_path.split("/")

        # Default ignore directories check
        if is_dir and name in IGNORE_DIRS:
            return True

        for pat in self.patterns:
            pat_clean = pat.rstrip("/")

            # Directory match
            if is_dir:
                if rel_path == pat_clean or rel_path.startswith(pat_clean + "/"):
                    return True
                if name == pat_clean:
                    return True

            # Full relative path exact or prefix match
            if rel_path == pat_clean or rel_path.startswith(pat_clean + "/"):
                return True

            # Match on base filename
            if fnmatch.fnmatch(name, pat):
                return True

            # Match wildcard relative path
            if fnmatch.fnmatch(rel_path, pat):
                return True

            # Match path segment if pattern has no slash (e.g. "dist" matches "src/dist/bundle.js")
            if "/" not in pat_clean and pat_clean in rel_segments:
                return True

        return False
