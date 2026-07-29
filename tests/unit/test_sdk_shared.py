"""Unit tests for karmasakshi.sdk._shared (pure, I/O-free helpers)."""

from __future__ import annotations

import httpx
import pytest

from karmasakshi.sdk._shared import auth_header, raise_for_status
from karmasakshi.sdk.errors import KarmaSakshiApiError


def _response(status_code: int, content: bytes = b"", json_body: object = None) -> httpx.Response:
    request = httpx.Request("GET", "http://testserver/x")
    if json_body is not None:
        return httpx.Response(status_code, json=json_body, request=request)
    return httpx.Response(status_code, content=content, request=request)


def test_raise_for_status_does_not_raise_on_2xx():
    raise_for_status(_response(200))
    raise_for_status(_response(204))


def test_raise_for_status_extracts_fastapi_detail_field():
    with pytest.raises(KarmaSakshiApiError) as exc_info:
        raise_for_status(_response(404, json_body={"detail": "manifest not found"}))
    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "manifest not found"


def test_raise_for_status_falls_back_to_raw_text_on_non_json_body():
    with pytest.raises(KarmaSakshiApiError) as exc_info:
        raise_for_status(_response(500, content=b"not json at all"))
    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "not json at all"


def test_raise_for_status_falls_back_to_raw_text_when_json_has_no_detail_key():
    with pytest.raises(KarmaSakshiApiError) as exc_info:
        raise_for_status(_response(422, json_body={"unrelated": "field"}))
    assert exc_info.value.status_code == 422


def test_auth_header_shape():
    assert auth_header("tok-123") == {"Authorization": "Bearer tok-123"}


def test_karma_sakshi_api_error_message_includes_status_and_detail():
    error = KarmaSakshiApiError(403, "cross-organization access denied")
    assert "403" in str(error)
    assert "cross-organization access denied" in str(error)
