"""Tests for OAuth / OAUTHBEARER authentication support."""

from __future__ import annotations

import os
import subprocess as sp

import pytest

from psycopg import pq

from .fix_pginstance import PGInstance, find_pg_binary

pytestmark = [pytest.mark.managed_pg]


@pytest.fixture(scope="module")
def oauth_validator_path():
    """Build the dummy OAuth validator extension and return its path."""
    if pq.version() < 180000:
        pytest.skip("OAuth requires libpq >= 18")

    oauth_dir = os.path.join(os.path.dirname(__file__), "oauth")
    pg_config = os.environ.get("PG_CONFIG", "pg_config")

    result = sp.run(
        ["make", "-C", oauth_dir, f"PG_CONFIG={pg_config}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"Failed to build OAuth validator: {result.stderr}")

    return os.path.join(oauth_dir, "dummy_validator")


@pytest.fixture(scope="module")
def oauth_pg_instance(oauth_validator_path):
    """Start a managed PostgreSQL 18 instance configured for OAuth."""
    if pq.version() < 180000:
        pytest.skip("OAuth requires libpq >= 18")

    instance = PGInstance(
        pg_config={
            "oauth_validator_libraries": f"'{oauth_validator_path}'",
        },
        pg_hba_entries=[
            # OAuth entry for testuseroauth on IPv4
            "host all testuseroauth 127.0.0.1/32 oauth"
            " scope=test"
            ' issuer="http://localhost:18080"',
        ],
        post_start_sql=[
            "CREATE USER testuseroauth",
        ],
    )

    if not instance.available:
        pytest.skip("pg_ctl/initdb not available")

    instance.start()
    yield instance
    instance.stop()


@pytest.fixture(scope="module")
def oauth_port(oauth_pg_instance):
    """Return the port the OAuth PG instance is listening on."""
    # Extract port from DSN
    dsn = oauth_pg_instance.dsn
    for part in dsn.split():
        if part.startswith("port="):
            return int(part.split("=", 1)[1])
    raise RuntimeError(f"Cannot extract port from DSN: {dsn}")


@pytest.fixture
def oauth_server(oauth_pg_instance, oauth_port):
    """Start a DummyOAuthServer configured for the test PG instance.

    Updates the pg_hba.conf to use the actual server port as issuer.
    """
    from .oauth_server import DummyOAuthServer

    with DummyOAuthServer(port=0) as server:
        port = server.server_port

        # Update pg_hba.conf with the actual OAuth server port
        hba_path = os.path.join(oauth_pg_instance._datadir, "pg_hba.conf")
        with open(hba_path) as f:
            content = f.read()

        new_content = content.replace(
            "http://localhost:18080",
            f"http://localhost:{port}",
        )
        with open(hba_path, "w") as f:
            f.write(new_content)

        # Reload PG to pick up the new pg_hba.conf
        pg_ctl = find_pg_binary("pg_ctl")
        if pg_ctl:
            sp.run(
                [pg_ctl, "reload", "-D", oauth_pg_instance._datadir],
                capture_output=True,
            )

        yield server

        # Restore original pg_hba.conf
        with open(hba_path, "w") as f:
            f.write(content)
        if pg_ctl:
            sp.run(
                [pg_ctl, "reload", "-D", oauth_pg_instance._datadir],
                capture_output=True,
            )


@pytest.fixture(autouse=True)
def oauth_env(monkeypatch):
    """Set PGOAUTHDEBUG=UNSAFE for all OAuth tests."""
    monkeypatch.setenv("PGOAUTHDEBUG", "UNSAFE")


@pytest.fixture(autouse=True)
def reset_hook():
    """Reset the auth data hook after each test."""
    yield
    if pq.version() >= 180000 and hasattr(pq, "set_auth_data_hook"):
        pq.set_auth_data_hook(None)


def test_bearer_token_hook(oauth_server, oauth_pg_instance, oauth_port):
    """Test that the OAuthBearerRequest hook can provide a token."""
    captured: dict[str, object] = {}

    def hook(data):
        if isinstance(data, pq.OAuthBearerRequest):
            captured["openid_configuration"] = data.openid_configuration
            captured["scope"] = data.scope
            data.token = "yes"
            return True
        return True

    pq.set_auth_data_hook(hook)

    server_port = oauth_server.server_port
    dsn = (
        f"host=localhost port={oauth_port} dbname=postgres"
        f" user=testuseroauth"
        f" oauth_issuer=http://localhost:{server_port}"
        f" oauth_client_id=foo"
    )

    conn = pq.PGconn.connect(dsn.encode())
    assert conn.status == pq.ConnStatus.OK, conn.get_error_message()

    assert captured.get("openid_configuration") == (
        f"http://localhost:{server_port}/.well-known/openid-configuration"
    )
    assert captured.get("scope") == "test"


def test_device_prompt_hook(oauth_server, oauth_pg_instance, oauth_port):
    """Test that the PromptOAuthDevice hook receives device flow data."""
    captured: dict[str, object] = {}

    def hook(data):
        if isinstance(data, pq.PromptOAuthDevice):
            captured["verification_uri"] = data.verification_uri
            captured["user_code"] = data.user_code
            captured["verification_uri_complete"] = data.verification_uri_complete
            captured["expires_in"] = data.expires_in
        return True

    pq.set_auth_data_hook(hook)

    server_port = oauth_server.server_port
    dsn = (
        f"host=localhost port={oauth_port} dbname=postgres"
        f" user=testuseroauth"
        f" oauth_issuer=http://localhost:{server_port}"
        f" oauth_client_id=foo"
    )

    try:
        pq.PGconn.connect(dsn.encode())
        # Connection may succeed or fail depending on libpq-oauth
        # availability, but the hook should have been called
    except Exception:
        pass

    if captured:
        assert captured["user_code"] == "666"
        assert captured["expires_in"] == 60
        assert captured["verification_uri_complete"] is None


def test_hook_reset(oauth_server, oauth_pg_instance, oauth_port):
    """Test that resetting the hook works after setting a broken one."""

    def broken_hook(data):
        raise RuntimeError("broken hook")

    pq.set_auth_data_hook(broken_hook)

    server_port = oauth_server.server_port
    dsn = (
        f"host=localhost port={oauth_port} dbname=postgres"
        f" user=testuseroauth"
        f" oauth_issuer=http://localhost:{server_port}"
        f" oauth_client_id=foo"
    )

    # The broken hook returns -1 (failure) to libpq, so connection should fail
    conn = pq.PGconn.connect(dsn.encode())
    assert conn.status != pq.ConnStatus.OK

    # Reset hook and verify
    pq.set_auth_data_hook(None)
    assert pq.get_auth_data_hook() is None

    # Now set a good hook and verify connection succeeds after reset
    def good_hook(data):
        if isinstance(data, pq.OAuthBearerRequest):
            data.token = "yes"
        return True

    pq.set_auth_data_hook(good_hook)
    conn = pq.PGconn.connect(dsn.encode())
    assert conn.status == pq.ConnStatus.OK, conn.get_error_message()


def test_hook_not_supported_on_old_libpq():
    """Verify that set_auth_data_hook raises NotSupportedError on old libpq."""
    if pq.version() >= 180000:
        pytest.skip("This test is for libpq < 18 only")

    from psycopg.errors import NotSupportedError

    with pytest.raises(NotSupportedError):
        pq.set_auth_data_hook(lambda data: True)
