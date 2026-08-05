import importlib.util
import json
import os
import time
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "submit_log.py"
SPEC = importlib.util.spec_from_file_location("submit_log", SCRIPT_PATH)
submit_log = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(submit_log)


def _configure_log_dir(monkeypatch, tmp_path):
    log_file = tmp_path / "session.jsonl"
    monkeypatch.setattr(submit_log, "LOG_DIR", tmp_path)
    monkeypatch.setattr(submit_log, "LOG_FILE", log_file)
    monkeypatch.setattr(submit_log, "ARCHIVE_DIR", tmp_path / "archive")
    return log_file


def _entry(prompt):
    return json.dumps({"prompt": prompt}) + "\n"


def test_recovers_stale_pending_before_live_entries(monkeypatch, tmp_path):
    log_file = _configure_log_dir(monkeypatch, tmp_path)
    pending = tmp_path / "session.pending.1.jsonl"
    pending.write_text(_entry("old"), encoding="utf-8")
    log_file.write_text(_entry("new"), encoding="utf-8")
    old_time = time.time() - submit_log.STALE_PENDING_SECONDS - 1
    os.utime(pending, (old_time, old_time))

    submit_log._recover_stale_pending()

    assert not pending.exists()
    assert log_file.read_text(encoding="utf-8") == _entry("old") + _entry("new")


def test_timeout_restores_pending_batch(monkeypatch, tmp_path):
    log_file = _configure_log_dir(monkeypatch, tmp_path)
    original = _entry("keep me")
    log_file.write_text(original, encoding="utf-8")
    monkeypatch.setattr(submit_log, "SERVER_URL", "https://example.invalid/ingest")
    monkeypatch.setattr(
        submit_log.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("timed out")),
    )

    with pytest.raises(SystemExit) as exc:
        submit_log.main()

    assert exc.value.code == 0
    assert log_file.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("session.pending.*.jsonl"))
