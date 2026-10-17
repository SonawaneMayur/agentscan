import json
from pathlib import Path

import pytest


@pytest.fixture
def write_config(tmp_path: Path):
    """Write a JSON config at tmp_path/<relative path> and return its path."""

    def write(relative: str, data: dict) -> Path:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        return path

    return write
