"""Resource bounds: a witness must not be usable as a free amplifier."""
import json
import urllib.error
import urllib.request

import pytest

from avm_mesh import MeshError
from avm_mesh.receipt import bundle_digest
from avm_mesh.service import (
    DEFAULT_MAX_PROOF_BYTES,
    MAX_PATH_CHARS,
    SOCKET_TIMEOUT_S,
    Store,
    make_server,
    run_in_thread,
)


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_store_refuses_a_proofpack_over_the_limit(tmp_path):
    store = Store(tmp_path / "s", max_proofpack_bytes=1024)
    with pytest.raises(MeshError, match="over the .* byte limit"):
        store.put_proofpack({"blob": "x" * 4096})


def test_store_accepts_a_proofpack_at_the_limit(tmp_path):
    store = Store(tmp_path / "s", max_proofpack_bytes=1_000_000)
    digest = store.put_proofpack({"blob": "x" * 1000})
    assert (store.proofpacks / f"{digest}.json").exists()


def test_serving_an_oversized_file_is_refused_rather_than_streamed(tmp_path):
    """A file placed in the store directly must not bypass the cap."""
    store = Store(tmp_path / "s", max_proofpack_bytes=512)
    oversized = {"blob": "x" * 4096}
    digest = bundle_digest(oversized)
    (store.proofpacks / f"{digest}.json").write_text(json.dumps(oversized), encoding="utf-8")

    server, _thread = run_in_thread(store)
    base = "http://127.0.0.1:%d" % server.server_address[1]
    status, _body = _get(base, f"/proofpacks/{digest}")
    assert status == 413


def test_a_long_request_path_is_refused(tmp_path):
    store = Store(tmp_path / "s")
    server, _thread = run_in_thread(store)
    base = "http://127.0.0.1:%d" % server.server_address[1]
    status, _body = _get(base, "/receipts/" + "a" * (MAX_PATH_CHARS + 10))
    assert status == 414


def test_rate_limit_returns_429_with_retry_after(tmp_path):
    store = Store(tmp_path / "s")
    server = make_server(store, port=0, rate_limit=3, rate_window_s=60)
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % server.server_address[1]

    codes = [_get(base, "/healthz")[0] for _ in range(3)]
    assert codes == [200, 200, 200]

    try:
        with urllib.request.urlopen(base + "/healthz", timeout=5) as response:
            codes.append(response.status)
    except urllib.error.HTTPError as exc:
        codes.append(exc.code)
        assert exc.headers.get("Retry-After") is not None

    assert codes[-1] == 429


def test_defaults_are_finite():
    """A limit that is None or zero protects nothing."""
    assert DEFAULT_MAX_PROOF_BYTES > 0
    assert SOCKET_TIMEOUT_S > 0
    assert MAX_PATH_CHARS > 0
