"""The fork's hardening: what a stolen token or an open internet address can no longer do."""

import pytest
from mcp.server.auth.provider import RegistrationError
from mcp.shared.auth import OAuthClientInformationFull

from claude_voice.oauth import MAX_CLIENTS, MAX_CONSENTS, OAuthProvider
from claude_voice.store import Store

SECRET = "the-owners-login-secret-0123456789abcdef"


def client(n=0, redirect="https://claude.ai/api/mcp/auth_callback"):
    return OAuthClientInformationFull(client_id=f"c{n}", redirect_uris=[redirect], token_endpoint_auth_method="none")


async def test_a_new_login_secret_signs_everyone_out(tmp_path):
    store = Store(tmp_path / "bridge.db")
    oauth = OAuthProvider(store, login_secret=SECRET, public_url="https://x")
    await oauth.register_client(client())
    tokens = await oauth.issue_tokens("c0", ["claude"], None)

    same = OAuthProvider(store, login_secret=SECRET, public_url="https://x")
    assert await same.load_access_token(tokens.access_token) is not None

    rotated = OAuthProvider(store, login_secret=SECRET + "-new", public_url="https://x")
    assert await rotated.load_access_token(tokens.access_token) is None
    assert await rotated.get_client("c0") is None


async def test_revoke_all_drops_every_token(tmp_path):
    oauth = OAuthProvider(Store(tmp_path / "bridge.db"), login_secret=SECRET, public_url="https://x")
    await oauth.register_client(client())
    tokens = await oauth.issue_tokens("c0", ["claude"], None)
    assert oauth.revoke_all() == 2
    assert await oauth.load_access_token(tokens.access_token) is None


async def test_only_allowed_hosts_may_receive_codes(tmp_path):
    oauth = OAuthProvider(
        Store(tmp_path / "bridge.db"), login_secret=SECRET, public_url="https://x", redirect_hosts=["claude.ai"]
    )
    await oauth.register_client(client())
    with pytest.raises(RegistrationError):
        await oauth.register_client(client(1, "https://evil.example/cb"))


async def test_registrations_are_capped(tmp_path):
    oauth = OAuthProvider(Store(tmp_path / "bridge.db"), login_secret=SECRET, public_url="https://x")
    for n in range(MAX_CLIENTS):
        await oauth.register_client(client(n))
        await oauth.issue_tokens(f"c{n}", ["claude"], None)
    with pytest.raises(RegistrationError):
        await oauth.register_client(client(MAX_CLIENTS))


async def test_idle_registrations_make_room(tmp_path):
    oauth = OAuthProvider(Store(tmp_path / "bridge.db"), login_secret=SECRET, public_url="https://x")
    for n in range(MAX_CLIENTS + 5):
        await oauth.register_client(client(n))
    assert await oauth.get_client(f"c{MAX_CLIENTS + 4}") is not None


async def test_pending_sign_ins_are_capped(tmp_path):
    from mcp.server.auth.provider import AuthorizationParams

    oauth = OAuthProvider(Store(tmp_path / "bridge.db"), login_secret=SECRET, public_url="https://x")
    params = AuthorizationParams(
        state=None,
        scopes=None,
        code_challenge="x" * 43,
        redirect_uri="https://claude.ai/cb",
        redirect_uri_provided_explicitly=True,
    )
    for _ in range(MAX_CONSENTS * 3):
        await oauth.authorize(client(), params)
    assert len(oauth._consents) == MAX_CONSENTS


def test_store_is_private(tmp_path):
    Store(tmp_path / "bridge.db")
    assert (tmp_path / "bridge.db").stat().st_mode & 0o777 == 0o600
