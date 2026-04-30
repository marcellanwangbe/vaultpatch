"""Tests for vaultpatch.template."""
import pytest
from vaultpatch.template import (
    TemplateError,
    TemplateResult,
    render_value,
    render_secret,
)


# ---------------------------------------------------------------------------
# render_value
# ---------------------------------------------------------------------------

def test_render_value_no_placeholders():
    assert render_value("hello world", {}) == "hello world"


def test_render_value_single_placeholder():
    result = render_value("{{env}}-secret", {"env": "prod"})
    assert result == "prod-secret"


def test_render_value_multiple_placeholders():
    result = render_value("{{host}}:{{port}}", {"host": "db", "port": "5432"})
    assert result == "db:5432"


def test_render_value_whitespace_inside_braces():
    result = render_value("{{ env }}", {"env": "staging"})
    assert result == "staging"


def test_render_value_missing_variable_raises():
    with pytest.raises(KeyError, match="region"):
        render_value("{{region}}-bucket", {})


# ---------------------------------------------------------------------------
# render_secret
# ---------------------------------------------------------------------------

def test_render_secret_all_keys():
    secret = {"url": "https://{{host}}/api", "token": "{{token}}"}
    variables = {"host": "example.com", "token": "abc123"}
    result = render_secret("secret/app", secret, variables)
    assert result.ok
    assert result.rendered["url"] == "https://example.com/api"
    assert result.rendered["token"] == "abc123"


def test_render_secret_records_error_for_missing_variable():
    secret = {"dsn": "postgres://{{user}}:{{pass}}@localhost/db"}
    result = render_secret("secret/db", secret, {"user": "admin"})
    assert not result.ok
    assert len(result.errors) == 1
    assert result.errors[0].key == "dsn"
    assert "pass" in result.errors[0].message


def test_render_secret_selective_keys():
    secret = {"a": "{{x}}", "b": "{{y}}", "c": "plain"}
    variables = {"x": "X"}
    result = render_secret("secret/misc", secret, variables, keys=["a", "c"])
    # 'a' rendered, 'c' has no placeholder so unchanged, 'b' skipped
    assert result.rendered["a"] == "X"
    assert result.rendered["c"] == "plain"
    assert result.rendered["b"] == "{{y}}"  # passed through unchanged
    assert result.ok


def test_render_secret_summary_ok():
    result = TemplateResult(path="secret/x", rendered={"k": "v"}, errors=[])
    assert "1 key(s) rendered successfully" in result.summary()


def test_render_secret_summary_with_errors():
    err = TemplateError(key="k", message="undefined variable 'z'")
    result = TemplateResult(path="secret/x", rendered={}, errors=[err])
    assert "1 error(s)" in result.summary()


def test_template_error_str():
    err = TemplateError(key="my_key", message="undefined variable 'foo'")
    assert str(err) == "[my_key] undefined variable 'foo'"
