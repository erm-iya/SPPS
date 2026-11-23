import os
import json
from typing import Optional
from ..models import ScanResult


class JSONReporter:
    """
    Exports scan results to a structured JSON file.
    """

    def __init__(self, result: ScanResult):
        self.result = result

    def export(self, filepath: str) -> None:
        data = self.result.to_dict()
        target_path = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
