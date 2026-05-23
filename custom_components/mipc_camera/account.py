"""
Implement the MIPCAccount that represents an account on MIPC 
with some methods to fetch data from mipcm.com.
"""

from time import time
from typing import Any
from json import loads as json_loads
from json import JSONDecodeError
from re import IGNORECASE, MULTILINE, sub
from hashlib import md5 as hashlib_md5
from secrets import randbits
import ssl
import math
from urllib.parse import parse_qs, urlparse

from asyncio import timeout, TimeoutError as AsyncioTimeoutError
from requests import Response, Session, Timeout, HTTPError, RequestException
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from homeassistant.core import HomeAssistant, HomeAssistantError

from .deps.crypto import encrypt
from .const import (
    LOGGER,
    BASE_HOST,
    TIMEOUT,
    PATHS,
    PRIME,
    ROOT_NUM,
    CAM_TIMEOUT,
    MAX_REQUEST_TRY,
)

MIPC_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
BOOTSTRAP_HOSTS = (
    BASE_HOST,
    "http://www.mipcm.com:7080",
    "http://www.mipcm.com",
    "https://oveu17.mipcm.com:7443",
    "http://oveu17.mipcm.com:7080",
)


def _int_to_min_bytes(value: int) -> bytes:
    """Encode integer to minimal big-endian bytes (at least 1 byte)."""
    if value < 0:
        raise ValueError("Negative integers are not supported")
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _js_to_int32(value: str | int | float) -> int:
    """Mimic JavaScript ToInt32 conversion used by the original mcodec helper."""
    number = float(value)
    if math.isnan(number) or math.isinf(number) or number == 0:
        return 0

    number = math.copysign(math.floor(abs(number)), number)
    int32 = int(number) % (2**32)
    if int32 >= 2**31:
        int32 -= 2**32

    return int32


def _encode_js_number_bytes(value: str | int | float) -> bytes:
    """Encode numbers exactly like the legacy JavaScript d() helper."""
    number = float(value)
    int32 = _js_to_int32(value)
    output = bytearray()

    for shift in (24, 16, 8, 0):
        if number >= (1 << shift):
            output.append((int32 >> shift) & 0xFF)

    return bytes(output)


def _decode_to_bytes(value: str | int | bytes | bytearray) -> bytes:
    """Convert JS-like number/hex input to bytes used by legacy nid builder."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    if isinstance(value, int):
        return _encode_js_number_bytes(value)

    text = str(value)
    if text.startswith("0x"):
        hex_part = text[2:]
        if len(hex_part) % 2:
            hex_part = f"0{hex_part}"
        return bytes.fromhex(hex_part)

    if text == "":
        return b""

    if text.isdigit():
        return _encode_js_number_bytes(text)

    return text.encode("latin-1", errors="ignore")


def _encode_base64_custom(data: bytes) -> str:
    """Encode binary payload using MIPC custom Base64 alphabet without padding."""
    out: list[str] = []

    for idx in range(0, len(data), 3):
        chunk = data[idx : idx + 3]
        b1 = chunk[0]
        b2 = chunk[1] if len(chunk) > 1 else 0
        b3 = chunk[2] if len(chunk) > 2 else 0

        i1 = b1 >> 2
        i2 = ((b1 & 0x03) << 4) | (b2 >> 4)
        i3 = ((b2 & 0x0F) << 2) | (b3 >> 6)
        i4 = b3 & 0x3F

        out.append(MIPC_BASE64_ALPHABET[i1])
        out.append(MIPC_BASE64_ALPHABET[i2])
        if len(chunk) > 1:
            out.append(MIPC_BASE64_ALPHABET[i3])
        if len(chunk) > 2:
            out.append(MIPC_BASE64_ALPHABET[i4])

    return "".join(out)


def _build_nid(seq: int, id_: str, shared_key: str, num: int) -> str:
    """Re-implement legacy mcodec.nid behavior without js2py."""
    seq_bytes = _decode_to_bytes(seq)
    id_bytes = _decode_to_bytes(id_) if id_ else b""
    num_bytes = _decode_to_bytes(num) if id_ else b""

    static_payload = b""
    if seq_bytes:
        static_payload += bytes([64 + len(seq_bytes)]) + seq_bytes
    if id_bytes:
        static_payload += bytes([96 + len(id_bytes)]) + id_bytes
    if num_bytes:
        static_payload += bytes([128 + len(num_bytes)]) + num_bytes

    digest_input = static_payload
    if shared_key:
        key_bytes = shared_key.encode("latin-1", errors="ignore")
        digest_input += bytes([len(key_bytes)]) + key_bytes

    digest_hex = hashlib_md5(digest_input).hexdigest()
    digest_bytes = _decode_to_bytes(f"0x{digest_hex}")

    token = bytes([32 + len(digest_bytes)]) + digest_bytes + static_payload
    return _encode_base64_custom(token)


def _gen_private_key() -> str:
    """Generate private DH value in the same range as the legacy implementation."""
    return str(randbits(64) or 1)


def _gen_public_key(private_key: str) -> str:
    """Generate public DH value."""
    return str(pow(int(ROOT_NUM), int(private_key), int(PRIME)))


def _gen_shared_secret(private_key: str, remote_public_key: str) -> str:
    """Generate DH shared secret."""
    return str(pow(int(remote_public_key), int(private_key), int(PRIME)))

class RequestError(HomeAssistantError):
    """Error raised in case of failed request to MIPC."""


class _LegacyTLSAdapter(HTTPAdapter):
    """HTTP adapter that allows legacy TLS handshakes used by old MIPC endpoints."""

    def __init__(self, verify: bool, *args, **kwargs) -> None:
        self._verify = verify
        super().__init__(*args, **kwargs)

    def _build_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()

        if not self._verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Some MIPC servers still rely on legacy ciphers/protocol negotiation.
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            context.options |= ssl.OP_LEGACY_SERVER_CONNECT

        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass

        try:
            context.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ValueError):
            pass

        return context

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._build_ssl_context()
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def _make_get_request(url: str, verify: bool = False) -> Response:
    """Make request synchronously with hass.async_add_executor_job."""
    session = Session()
    session.mount("https://", _LegacyTLSAdapter(verify=verify))

    response = session.get(url, timeout=TIMEOUT, verify=verify)
    response.raise_for_status()
    setattr(response, "_mipc_session", session)

    return response


def _close_response(response: Response) -> None:
    """Close response and attached transient session."""
    response.close()
    session: Session | None = getattr(response, "_mipc_session", None)
    if session is not None:
        session.close()


class MIPCAccount:
    """represents an account on MIPC with some methods to fetch data from mipcm.com."""
    def __init__(self, username: str, password: str) -> None:
        self._username: str = username
        self._password: str = password

        self._last_authentication: float | None = None

        self._host: str | None = None

        self._qid: str | None = None
        self._seq: int = 0
        self._private: str = _gen_private_key()
        self._public: str = _gen_public_key(self._private)
        self._shared_key: str | None = None
        self._key: str | None = None
        self._lid: str | None = None
        self._shared_key: str | None = None
        self._encrypted_password: str | None = None
        self._sid: str | None = None
        self._nid: str | None = None
        self._device_tokens: dict[str, str] = {}


    def parse_response(self, response: str) -> dict:
        """
        Parse JS message from mipcm.com as JSON.
        
        Responses from mipcm.com are formatted as follows :
        message({some_json:"but without quotation marks (as in javascript)"})
        """
        if not response.startswith("message("):
            raise RequestError("Unexpected response format from MIPC API")

        try:
            response_json = sub(
                r"(?P<b>[\{\[,])(?P<sb>\s?)(?P<k>[a-z0-9_\.]+)(?P<a>:)(?P<sa>\s?)",
                '\\g<b>"\\g<k>"\\g<a>',
                response[8:-2],
                0,
                IGNORECASE | MULTILINE,
            )

            return json_loads(response_json)
        except (TypeError, ValueError, JSONDecodeError) as err:
            raise RequestError("Failed to parse MIPC API response") from err

    def url(
        self,
        path_name: str,
        params: dict[str, str] | None = None,
        host: str | None = None,
    ) -> str:
        """Generates a URL for making requests to the MIPC service."""
        if not host:
            host = self._host if self._host else BASE_HOST
        if not params:
            params = {}

        self._seq += 1

        params_list = [f"hfrom_handle={self._seq}"]
        for param in params.keys():
            params_list.append(f"{param}={params[param]}")

        return f"{host}{PATHS[path_name]}?{'&'.join(params_list)}"

    async def get(
        self,
        path_name: str,
        hass: HomeAssistant,
        params: dict[str, str] | None = None,
        https: bool = False,
        host: str | None = None,
    ) -> dict | None:
        """
        Performs an HTTP GET request to the specified 
        path and returns the parsed JSON response.
        """
        if not params:
            params = {}

        url = self.url(path_name, params, host=host)
        error: str | None = None
        response_json: dict[str, Any] | None = None

        try:
            async with timeout(TIMEOUT):
                response: Response = await hass.async_add_executor_job(
                    _make_get_request, url, https
                )
                try:
                    response_data = response.text
                finally:
                    _close_response(response)

                response_json = self.parse_response(response_data)
                if (
                    "data" in response_json
                    and "result" in response_json["data"]
                    and isinstance(response_json["data"]["result"], str)
                    and response_json["data"]["result"] != ""
                ):
                    error = f"Error getting {url} : {response_json['data']['result']}"
                elif (
                    "data" in response_json
                    and "ret" in response_json["data"]
                    and "reason" in response_json["data"]["ret"]
                    and isinstance(response_json["data"]["ret"]["reason"], str)
                    and response_json["data"]["ret"]["reason"] != ""
                ):
                    error = (
                        f"Error getting {url} : {response_json['data']['ret']['reason']}"
                    )
                elif (
                    "data" in response_json
                    and "Result" in response_json["data"]
                    and "Reason" in response_json["data"]["Result"]
                    and isinstance(response_json["data"]["Result"]["Reason"], str)
                    and response_json["data"]["Result"]["Reason"] != ""
                ):
                    error = f"Error getting {url} : {response_json['data']['Result']['Reason']}"
        except AsyncioTimeoutError:
            error = f"Timeout getting '{url}'"
        except Timeout:
            error = f"Timeout getting '{url}'"
        except HTTPError as err:
            error = f"Error getting '{url}' : {err}"
        except RequestException as err:
            error = f"Request failed for '{url}' : {err}"
        except RequestError:
            raise
        except Exception as err:  # pylint: disable=broad-except
            error = f"Unexpected error while getting '{url}' : {err}"

        if error:
            raise RequestError(error)

        return response_json

    async def retry_if_error(
        self, method: str, hass: HomeAssistant, params: dict | None = None
    ) -> Any | None:
        """
        Retries a specified method if an error occurs up to 
        a maximum number of retries MAX_REQUEST_TRY.
        """
        if not params:
            params = {}

        try_count = 0

        while try_count < MAX_REQUEST_TRY:
            try:
                try_count += 1
                return await getattr(self, method)(hass=hass, in_retry_loop=True, **params)
            except HomeAssistantError as err:
                LOGGER.error("(try: %s) %s", method, err)
                await self.clear_values()

        return None

    async def get_mipc_host(self, hass: HomeAssistant) -> str | None:
        """Retrieves the MIPC host."""

        LOGGER.debug("Getting host")

        last_error: RequestError | None = None
        for bootstrap_host in BOOTSTRAP_HOSTS:
            LOGGER.debug("Trying bootstrap host: %s", bootstrap_host)
            try:
                response = await self.get(
                    path_name="HOSTS", https=False, host=bootstrap_host, hass=hass
                )
                if not response:
                    continue

                signal_hosts = response.get("data", {}).get("server", {}).get("signal", [])
                if not isinstance(signal_hosts, list) or not signal_hosts:
                    raise RequestError("Invalid host payload returned by MIPC API")

                # Prefer HTTP signaling host to avoid legacy TLS handshake issues.
                preferred_host = next(
                    (item for item in signal_hosts if isinstance(item, str) and item.startswith("http://") and "/ccm" in item),
                    None,
                )

                if not preferred_host:
                    preferred_host = next(
                        (item for item in signal_hosts if isinstance(item, str) and "/ccm" in item),
                        None,
                    )

                if not preferred_host:
                    raise RequestError("No usable signal host returned by MIPC API")

                self._host = preferred_host
                LOGGER.info("Using MIPC signal host: %s", self._host)
                return self._host
            except RequestError as err:
                LOGGER.debug("Bootstrap host failed: %s (%s)", bootstrap_host, err)
                last_error = err

        if last_error is not None:
            raise last_error

        return None

    @staticmethod
    def _extract_token_from_uri(uri: str) -> str | None:
        """Extract stream token from a play/media URI."""
        try:
            parsed = urlparse(uri)
            params = parse_qs(parsed.query)
        except Exception:
            return None

        for key in ("dtoken", "token", "auth"):
            values = params.get(key)
            if values and values[0]:
                return values[0]

        return None

    async def _request_play_uri(self, hass: HomeAssistant, device_name: str) -> str:
        """Request fresh play URI and store matching still-image token for device."""
        if not self._sid:
            await self.auth(hass=hass)

        nid = await self.generate_nid(self._sid, 0, hass=hass)

        response = await self.get(
            path_name="PLAY",
            params={
                "hqid": self._qid,
                "dsess": 1,
                "dsess_nid": nid,
                "dsess_sn": device_name,
                "dsetup": 1,
                "dsetup_stream": "RTSP",
                "dsetup_trans": 1,
                "dsetup_trans_proto": "rtsp",
                "dtoken": "p0",
            },
            hass=hass,
        )

        uri = response.get("data", {}).get("MediaUri", {}).get("Uri") if response else None
        if not uri:
            raise RequestError("Missing media uri in play response")

        token = self._extract_token_from_uri(uri)
        if token:
            # STILL_IMAGE usually expects p1-prefixed token while PLAY returns p0.
            if token.startswith("p0"):
                token = f"p1{token[2:]}"
            self._device_tokens[device_name] = token

        return uri

    async def get_qid(
        self, hass: HomeAssistant, in_retry_loop: bool = False
    ) -> str | None:
        """Retrieves the QID (Query ID) used for authentication."""
        if not in_retry_loop:
            return await self.retry_if_error(method="get_qid", hass=hass)

        await self.check_timeout()
        if not self._host:
            await self.get_mipc_host(hass=hass)

        LOGGER.debug("Getting QID")

        response = await self.get(path_name="CREATE_SESSION", hass=hass)

        if response:
            qid = response.get("data", {}).get("qid")
            if not qid:
                raise RequestError("Missing qid in MIPC session response")

            self._qid = qid
            return qid

        return None

    async def generate_dh(
        self, hass: HomeAssistant, in_retry_loop: bool = False
    ) -> str | None:
        """Generates Diffie-Hellman keys."""
        if not in_retry_loop:
            return await self.retry_if_error(method="generate_dh", hass=hass)

        await self.check_timeout()
        if not self._qid:
            await self.get_qid(hass=hass)

        LOGGER.debug("Generating DH")

        response = await self.get(
            path_name="KEY",
            params={
                "dbnum_prime": PRIME,
                "dkey_a2b": self._public,
                "droot_num": ROOT_NUM,
            },
            hass=hass,
        )

        if response:
            self._key = response.get("data", {}).get("key_b2a")
            self._lid = response.get("data", {}).get("lid")
            if not self._key or not self._lid:
                raise RequestError("Missing DH fields in MIPC response")

            await self.generate_shared_key(hass=hass)
            return self._key

        return None

    async def auth(
        self, hass: HomeAssistant, in_retry_loop: bool = False
    ) -> str | None:
        """Performs user authentication with the MIPC service."""
        if not in_retry_loop:
            return await self.retry_if_error(method="auth", hass=hass)

        await self.check_timeout()
        if not self._shared_key:
            await self.generate_dh(hass=hass)

        await self.crypt_password(hass=hass)

        self._nid = await self.generate_nid(self._lid, 2, hass=hass)

        LOGGER.debug("Authentication")

        response = await self.get(
            path_name="LOGIN",
            params={
                "hqid": self._qid,
                "dlid": self._lid,
                "dnid": self._nid,
                "duser": self._username,
                "dpass": self._encrypted_password,
                "dsession_req": 1,
            },
            hass=hass,
        )

        if response:
            sid = response.get("data", {}).get("sid")
            if not sid:
                raise RequestError("Authentication failed: missing sid")

            self._sid = sid
            return sid

        return None

    async def get_devices(
        self, hass: HomeAssistant, in_retry_loop: bool = False
    ) -> dict | None:
        """Retrieves all cameras connected to the MIPC account."""
        if not in_retry_loop:
            return await self.retry_if_error(method="get_devices", hass=hass)

        await self.check_timeout()
        if not self._nid:
            await self.auth(hass=hass)

        LOGGER.debug("Getting devices")

        response = await self.get(
            path_name="DEVICES",
            params={
                "hqid": self._qid,
                "dsess": 1,
                "dsess_nid": self._nid,
                "dstart": 0,
                "dcounts": 1024,
            },
            hass=hass,
        )

        if response:
            return response["data"]["devs"]

        return None

    async def get_stream_source(
        self, device_name: str, hass: HomeAssistant, in_retry_loop: bool = False
    ) -> str | None:
        """Retrieves the stream source for a specific device."""
        if not in_retry_loop:
            return await self.retry_if_error(
                method="get_stream_source", params={"device_name": device_name}, hass=hass
            )

        if not device_name:
            return None

        await self.check_timeout()

        LOGGER.debug("Getting stream source")
        return await self._request_play_uri(hass=hass, device_name=device_name)

    async def get_still_image(
        self, hass: HomeAssistant, device_name: str, in_retry_loop: bool = False
    ) -> bytes | None:
        """Retrieves a still image for a specific device."""
        if not in_retry_loop:
            return await self.retry_if_error(
                method="get_still_image", hass=hass, params={"device_name": device_name}
            )

        if not self._sid:
            await self.auth(hass=hass)

        # Fetch a fresh token before each still-image request.
        await self._request_play_uri(hass=hass, device_name=device_name)

        nid = await self.generate_nid(self._sid, 0, hass=hass)

        LOGGER.debug("Getting still image")

        url = self.url(
            "STILL_IMAGE",
            {
                "dsess": 1,
                "dsess_nid": nid,
                "dsess_sn": device_name,
                "dtoken": self._device_tokens.get(device_name, "p1_xxxxxxxxxx"),
                "dencode_type": 0,
                "dpic_types_support": 2,
                "dflag": 2,
            },
        )
        try:
            async with timeout(TIMEOUT):
                response: Response = await hass.async_add_executor_job(
                    _make_get_request, url
                )
                try:
                    response_data = response.content
                finally:
                    _close_response(response)

                return response_data
        except AsyncioTimeoutError:
            LOGGER.error("Timeout getting '%s'", url)
        except Timeout:
            LOGGER.error("Timeout getting '%s'", url)
        except HTTPError as err:
            LOGGER.error("Error getting '%s' : %s", url, err)

    async def generate_shared_key(self, hass: HomeAssistant) -> str:
        """Generates a shared secret key."""
        if not self._key:
            await self.generate_dh(hass=hass)

        LOGGER.debug("Generating shared key")

        self._shared_key = _gen_shared_secret(self._private, self._key)

        return self._shared_key

    async def crypt_password(self, hass: HomeAssistant) -> str:
        """Encrypts the user's password."""
        if not self._shared_key:
            await self.generate_dh(hass=hass)

        LOGGER.debug("Encrypting password")

        self._encrypted_password = encrypt(self._password, self._shared_key)

        return self._encrypted_password

    async def generate_nid(self, id_: str, num: int, hass: HomeAssistant) -> str:
        """Generates a NID (Network ID)."""
        await self.check_timeout()
        if not self._shared_key:
            await self.generate_dh(hass=hass)

        LOGGER.debug("Generating NID")

        return _build_nid(self._seq, id_, self._shared_key, num)

    async def clear_values(self) -> None:
        """Clears stored values for new authentication."""
        LOGGER.debug("Clearing values")
        self._qid = None
        self._shared_key = None
        self._key = None
        self._lid = None
        self._shared_key = None
        self._encrypted_password = None
        self._sid = None
        self._nid = None

        self._private = _gen_private_key()
        self._public = _gen_public_key(self._private)

    async def check_timeout(self) -> None:
        """Checks if the authentication has timed out and clears session data if necessary."""
        if not self._last_authentication:
            self._last_authentication = time()

        if time() - self._last_authentication >= CAM_TIMEOUT / 1000:
            await self.clear_values()
            self._last_authentication = time()
