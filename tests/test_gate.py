import httpx
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from claude_voice.gate import AddressGate

ANTHROPIC = "160.79.104.0/21"


def app(allowed, header="x-forwarded-for", client=("127.0.0.1", 5000), sign_in=None):
    inner = Starlette(routes=[Route("/{p:path}", lambda r: PlainTextResponse("in"))])
    transport = httpx.ASGITransport(app=AddressGate(inner, allowed, header, sign_in), client=client)
    return httpx.AsyncClient(transport=transport, base_url="http://bridge")


async def test_from_the_internet_only_allowed_addresses_get_past_the_gate():
    async with app([ANTHROPIC]) as http:
        assert (await http.get("/mcp", headers={"x-forwarded-for": "160.79.105.7"})).status_code == 200
        assert (await http.get("/mcp", headers={"x-forwarded-for": "203.0.113.9"})).status_code == 403


async def test_a_caller_cannot_forge_its_way_in():
    async with app([ANTHROPIC]) as http:
        r = await http.get("/mcp", headers={"x-forwarded-for": "160.79.105.7, 203.0.113.9"})
        assert r.status_code == 403


async def test_health_stays_open():
    async with app([ANTHROPIC]) as http:
        assert (await http.get("/healthz", headers={"x-forwarded-for": "203.0.113.9"})).status_code == 200


async def test_behind_a_tunnel_a_request_without_the_tunnel_s_header_is_a_stranger():
    async with app([ANTHROPIC]) as http:
        assert (await http.get("/mcp")).status_code == 403
        assert (await http.get("/mcp", headers={"x-forwarded-for": "127.0.0.1"})).status_code == 403


async def test_without_a_tunnel_local_tools_pass():
    async with app([ANTHROPIC], header=None) as http:
        assert (await http.get("/mcp")).status_code == 200


async def test_without_a_header_the_connection_address_counts():
    async with app([ANTHROPIC], header=None, client=("203.0.113.9", 5000)) as http:
        assert (await http.get("/mcp")).status_code == 403


async def test_the_owner_s_browser_reaches_the_sign_in_pages_from_anywhere():
    async with app([ANTHROPIC]) as http:
        for path in ("/authorize", "/oauth/consent"):
            assert (await http.get(path, headers={"x-forwarded-for": "203.0.113.9"})).status_code == 200
        assert (await http.post("/token", headers={"x-forwarded-for": "203.0.113.9"})).status_code == 403


async def test_the_sign_in_pages_open_only_to_the_owner_s_own_networks_when_they_are_named():
    async with app([ANTHROPIC], sign_in=["100.64.0.0/10"]) as http:
        for path in ("/authorize", "/oauth/consent"):
            assert (await http.get(path, headers={"x-forwarded-for": "100.90.196.23"})).status_code == 200
            assert (await http.get(path, headers={"x-forwarded-for": "203.0.113.9"})).status_code == 403
        assert (await http.post("/mcp", headers={"x-forwarded-for": "100.90.196.23"})).status_code == 403
