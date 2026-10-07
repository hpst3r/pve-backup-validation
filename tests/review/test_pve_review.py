"""Adversarial review: ``pbv.pve.PveClient`` error contract and secret hygiene."""

from __future__ import annotations

import http.client
import socket
from collections.abc import Iterator

import pytest

from pbv.core import ApiError
from pbv.pve import PveClient

SECRET = "SENTINEL\r\nX-Injected: 1"


@pytest.fixture
def listener() -> Iterator[int]:
    """A TCP socket that accepts connections (via backlog) but never answers."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(8)
        yield s.getsockname()[1]


def test_invalid_header_value_becomes_secret_free_api_error(listener: int) -> None:
    client = PveClient("127.0.0.1", "restore01", "pbv@pve!t", SECRET, port=listener, verify_tls=False, retries=0)
    client._connection = lambda: http.client.HTTPConnection("127.0.0.1", listener, timeout=1)  # type: ignore[method-assign]
    with pytest.raises(ApiError) as info:
        client.version()
    assert "SENTINEL" not in str(info.value)
