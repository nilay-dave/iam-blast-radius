import json
import logging

from ibr.logging import JsonFormatter, configure, get_logger


def test_record_renders_as_single_line_json():
    record = logging.LogRecord("t", logging.INFO, "f.py", 1, "hello", None, None)
    rendered = JsonFormatter().format(record)
    assert "\n" not in rendered
    payload = json.loads(rendered)
    assert payload["message"] == "hello"
    assert payload["level"] == "info"
    assert payload["logger"] == "t"
    assert payload["run_id"]


def test_extra_fields_are_promoted_to_top_level():
    record = logging.LogRecord("t", logging.INFO, "f.py", 1, "m", None, None)
    record.rule_count = 18
    record.blind_pct = 66.7
    payload = json.loads(JsonFormatter().format(record))
    assert payload["rule_count"] == 18
    assert payload["blind_pct"] == 66.7


def test_reserved_attributes_are_not_leaked():
    record = logging.LogRecord("t", logging.INFO, "f.py", 1, "m", None, None)
    payload = json.loads(JsonFormatter().format(record))
    assert "pathname" not in payload
    assert "levelno" not in payload


def test_exception_is_serialized():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord("t", logging.ERROR, "f.py", 1, "failed", None, sys.exc_info())
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exception"]


def test_configure_is_idempotent():
    root = logging.getLogger()
    original = list(root.handlers)
    try:
        root.handlers = []
        configure("INFO")
        assert len(root.handlers) == 1
        configure("INFO")
        assert len(root.handlers) == 1
    finally:
        root.handlers = original


def test_get_logger_returns_named_logger():
    assert get_logger("ibr.test").name == "ibr.test"


def test_handler_follows_a_replaced_stderr():
    """Regression: binding sys.stderr at configure time made every log call
    raise a logging error once a test harness swapped the stream."""
    import io
    import sys

    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_stderr = sys.stderr
    try:
        configure("INFO")
        captured = io.StringIO()
        sys.stderr = captured
        get_logger("ibr.swap").info("after swap", extra={"marker": 1})
        payload = json.loads(captured.getvalue().strip())
        assert payload["message"] == "after swap"
        assert payload["marker"] == 1
    finally:
        sys.stderr = original_stderr
        root.handlers = original_handlers


def test_closed_stream_does_not_break_logging():
    import io
    import sys

    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_stderr = sys.stderr
    try:
        configure("INFO")
        closed = io.StringIO()
        closed.close()
        sys.stderr = closed
        sys.stderr = original_stderr
        live = io.StringIO()
        sys.stderr = live
        get_logger("ibr.recover").info("still logging")
        assert "still logging" in live.getvalue()
    finally:
        sys.stderr = original_stderr
        root.handlers = original_handlers
