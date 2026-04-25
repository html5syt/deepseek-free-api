"""
Deepseek Free API – AstrBot Plugin
====================================
Provides a local OpenAI-compatible HTTP server that proxies requests to
DeepSeek's web interface without requiring an official API key.

Features
--------
* Streaming and non-streaming chat completions
* Deep-thinking (R1 / think) mode, web-search mode, expert mode,
  silent/fold variants
* Token liveness check endpoint
* Model list endpoint
* DeepSeek PoW (Proof-of-Work) challenge solver implemented in pure Python
* Per-AstrBot-conversation DeepSeek session binding via unified_msg_origin (UMO)

Configuration (AstrBot plugin config)
--------------------------------------
* port             : int  – local server port (default 5566)
* client_identifier: str  – opaque string that clients set in the
                            `X-from-which-astrbot` request header to signal
                            they are AstrBot-sourced requests; when present
                            the plugin tracks the DeepSeek session per UMO.
* deepseek_token   : str  – optional DeepSeek refresh-token override
                            (overrides the Authorization header value
                            sent by the caller)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import re
import sqlite3
import string
import time
import uuid
from typing import AsyncGenerator, Optional

import aiohttp
from aiohttp import web

import astrbot.api.star as star
from astrbot.api import logger, AstrBotConfig
from astrbot.api.event import filter as event_filter
from astrbot.api.event import AstrMessageEvent
from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderRequest
from astrbot.core.star.config import put_config
from astrbot.core.utils.astrbot_path import get_astrbot_data_path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MODEL_NAME = "deepseek-chat"
_ACCESS_TOKEN_EXPIRES = 3600  # seconds
_MAX_RETRY = 3
_RETRY_DELAY = 5.0  # seconds
_FAKE_HEADERS: dict[str, str] = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Origin": "https://chat.deepseek.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://chat.deepseek.com/",
    "Sec-Ch-Ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/134.0.0.0 Safari/537.36"
    ),
    "X-App-Version": "20241129.1",
    "X-Client-Locale": "zh_CN",
    "X-Client-Platform": "web",
    "X-Client-Version": "1.7.1",
}
# Marker prefix injected into system prompt by on_llm_request hook
_NONCE_MARKER_PREFIX = "[[ASTRBOT_NONCE:"
_NONCE_MARKER_SUFFIX = "]]"

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _unix_ts() -> int:
    return int(time.time())


def _ms_ts() -> int:
    return int(time.time() * 1000)


def _random_hex(n: int) -> str:
    return "".join(random.choices(string.hexdigits[:16], k=n))


def _new_uuid(sep: bool = True) -> str:
    u = str(uuid.uuid4())
    return u if sep else u.replace("-", "")


def _random_str(charset: str = "hex", length: int = 18) -> str:
    if charset == "hex":
        return _random_hex(length)
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _cookie() -> str:
    ts = _unix_ts()
    return (
        f"intercom-HWWAFSESTIME={_ms_ts()}; "
        f"HWWAFSESID={_random_str('hex', 18)}; "
        f"Hm_lvt_{_new_uuid(False)}={ts},{ts},{ts}; "
        f"Hm_lpvt_{_new_uuid(False)}={ts}; "
        f"_frid={_new_uuid()}; "
        f"_fr_ssid={_new_uuid()}; "
        f"_fr_pvid={_new_uuid()}"
    )


# ---------------------------------------------------------------------------
# DeepSeek PoW solver (pure Python port of the WASM-backed TypeScript impl)
# The DeepSeekHashV1 algorithm:
#   Find the smallest non-negative integer `answer` such that
#   SHA3-256( f"{salt}_{expire_at}_{answer}" ) has >= `difficulty` leading
#   zero bits.
# ---------------------------------------------------------------------------


def _solve_pow(
    algorithm: str,
    challenge: str,  # included in the signed response sent to DeepSeek for server-side verification
    salt: str,
    difficulty: int,
    expire_at: int,
) -> int:
    """Return the PoW answer integer (raises RuntimeError if unsolvable)."""
    if algorithm != "DeepSeekHashV1":
        raise ValueError(f"Unsupported PoW algorithm: {algorithm}")
    prefix = f"{salt}_{expire_at}_"
    for answer in range(10_000_000):
        digest = hashlib.sha3_256(f"{prefix}{answer}".encode()).digest()
        # Count leading zero bits
        zero_bits = 0
        for byte in digest:
            if byte == 0:
                zero_bits += 8
            else:
                zero_bits += 8 - byte.bit_length()
                break
        if zero_bits >= difficulty:
            return answer
    raise RuntimeError("DeepSeek PoW: failed to find solution within limit")


def _build_pow_response(challenge_data: dict, target_path: str) -> str:
    """Solve the challenge and return the base64-encoded JSON response."""
    answer = _solve_pow(
        algorithm=challenge_data["algorithm"],
        challenge=challenge_data["challenge"],
        salt=challenge_data["salt"],
        difficulty=challenge_data["difficulty"],
        expire_at=challenge_data["expire_at"],
    )
    payload = {
        "algorithm": challenge_data["algorithm"],
        "challenge": challenge_data["challenge"],
        "salt": challenge_data["salt"],
        "answer": answer,
        "signature": challenge_data["signature"],
        "target_path": target_path,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


# ---------------------------------------------------------------------------
# DeepSeek API client (async, per-plugin-instance state)
# ---------------------------------------------------------------------------


class DeepSeekClient:
    """Manages tokens, sessions, and communication with DeepSeek's web API."""

    # commit-id updated periodically by _auto_update_version
    _event_commit_id: str = "6cf9c15d"

    def __init__(self) -> None:
        self._access_token_map: dict[str, dict] = {}
        # queue maps: refresh_token -> list of futures waiting for a token
        self._token_queues: dict[str, list[asyncio.Future]] = {}
        self._ip_address: str = ""
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # HTTP session management
    # ------------------------------------------------------------------

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # IP address
    # ------------------------------------------------------------------

    async def get_ip_address(self) -> str:
        if self._ip_address:
            return self._ip_address
        try:
            async with self._get_session().get(
                "https://chat.deepseek.com/",
                headers={**_FAKE_HEADERS, "Cookie": _cookie()},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                text = await resp.text()
        except Exception as exc:
            logger.warning(f"[deepseek-free-api] get_ip_address failed: {exc}")
            return "127.0.0.1"
        match = re.search(r'<meta name="ip" content="([\d.]+)">', text)
        if match:
            self._ip_address = match.group(1)
            logger.info(f"[deepseek-free-api] Current IP: {self._ip_address}")
        return self._ip_address or "127.0.0.1"

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    async def _request_token(self, refresh_token: str) -> dict:
        """Fetch a fresh access token using the refresh token."""
        if refresh_token in self._token_queues:
            # Another coroutine is already fetching – queue up
            loop = asyncio.get_event_loop()
            fut: asyncio.Future = loop.create_future()
            self._token_queues[refresh_token].append(fut)
            return await fut

        self._token_queues[refresh_token] = []
        try:
            async with self._get_session().get(
                "https://chat.deepseek.com/api/v0/users/current",
                headers={
                    "Authorization": f"Bearer {refresh_token}",
                    **_FAKE_HEADERS,
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json(content_type=None)
            biz = self._check_result(data, refresh_token)
            token = biz.get("token", refresh_token)
            result = {
                "accessToken": token,
                "refreshToken": token,
                "refreshTime": _unix_ts() + _ACCESS_TOKEN_EXPIRES,
            }
        except Exception as exc:
            result = exc  # type: ignore[assignment]
        finally:
            waiters = self._token_queues.pop(refresh_token, [])
            for fut in waiters:
                if not fut.done():
                    if isinstance(result, Exception):
                        fut.set_exception(result)
                    else:
                        fut.set_result(result)

        if isinstance(result, Exception):
            raise result
        logger.info("[deepseek-free-api] Token refreshed successfully")
        return result

    async def acquire_token(self, refresh_token: str) -> str:
        """Return a (possibly cached) access token."""
        entry = self._access_token_map.get(refresh_token)
        if entry is None or _unix_ts() > entry["refreshTime"]:
            entry = await self._request_token(refresh_token)
            self._access_token_map[refresh_token] = entry
        return entry["accessToken"]

    # ------------------------------------------------------------------
    # Session creation
    # ------------------------------------------------------------------

    async def create_session(self, refresh_token: str) -> str:
        """Create a new DeepSeek chat session and return its ID."""
        token = await self.acquire_token(refresh_token)
        async with self._get_session().post(
            "https://chat.deepseek.com/api/v0/chat_session/create",
            json={"character_id": None},
            headers={
                "Authorization": f"Bearer {token}",
                **_FAKE_HEADERS,
            },
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data = await resp.json(content_type=None)
        biz = self._check_result(data, refresh_token)
        if not biz or "chat_session" not in biz:
            raise RuntimeError(
                "create_session: no chat_session in response – account/IP may be banned"
            )
        return biz["chat_session"]["id"]

    # ------------------------------------------------------------------
    # PoW challenge
    # ------------------------------------------------------------------

    async def get_pow_header(self, refresh_token: str, target_path: str) -> str:
        """Return a solved PoW base64 header value for `target_path`."""
        token = await self.acquire_token(refresh_token)
        async with self._get_session().post(
            "https://chat.deepseek.com/api/v0/chat/create_pow_challenge",
            json={"target_path": target_path},
            headers={
                "Authorization": f"Bearer {token}",
                **_FAKE_HEADERS,
            },
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            data = await resp.json(content_type=None)
        challenge = self._check_result(data, refresh_token)["challenge"]
        return await asyncio.get_event_loop().run_in_executor(
            None, _build_pow_response, challenge, target_path
        )

    # ------------------------------------------------------------------
    # Thinking quota
    # ------------------------------------------------------------------

    async def get_thinking_quota(self, refresh_token: str) -> int:
        """Return remaining deep-thinking quota (0 means none available)."""
        try:
            async with self._get_session().get(
                "https://chat.deepseek.com/api/v0/users/feature_quota",
                headers={
                    "Authorization": f"Bearer {refresh_token}",
                    **_FAKE_HEADERS,
                    "Cookie": _cookie(),
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json(content_type=None)
            biz = self._check_result(data, refresh_token)
            if not biz:
                return 0
            thinking = biz.get("thinking", {})
            quota = thinking.get("quota", 0)
            used = thinking.get("used", 0)
            remaining = quota - used
            logger.info(f"[deepseek-free-api] Thinking quota: {remaining}/{quota}")
            return remaining
        except Exception as exc:
            logger.warning(f"[deepseek-free-api] get_thinking_quota failed: {exc}")
            return 0

    # ------------------------------------------------------------------
    # Response checker
    # ------------------------------------------------------------------

    def _check_result(self, data: dict, refresh_token: str) -> dict:
        code = data.get("code")
        if code is None:
            return data
        if code == 0:
            return data.get("data") or data.get("biz_data") or {}
        if code == 40003:
            self._access_token_map.pop(refresh_token, None)
        msg = data.get("msg", "unknown error")
        raise RuntimeError(f"DeepSeek API error {code}: {msg}")

    # ------------------------------------------------------------------
    # Message preparation (port of messagesPrepare from TypeScript)
    # ------------------------------------------------------------------

    @staticmethod
    def messages_prepare(messages: list[dict]) -> str:
        """Convert OpenAI-format messages into DeepSeek prompt string."""
        processed: list[dict] = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                texts = [
                    item.get("text", "")
                    for item in content
                    if item.get("type") == "text"
                ]
                text = "\n".join(texts)
            else:
                text = str(content)
            if text.endswith("FINISHED"):
                text = text[:-8].rstrip()
            processed.append({"role": msg.get("role", "user"), "text": text})

        if not processed:
            return ""

        # Merge consecutive same-role blocks
        merged: list[dict] = []
        current = dict(processed[0])
        for item in processed[1:]:
            if item["role"] == current["role"]:
                current["text"] += "\n\n" + item["text"]
            else:
                merged.append(current)
                current = dict(item)
        merged.append(current)

        parts: list[str] = []
        for i, block in enumerate(merged):
            role = block["role"]
            text = block["text"]
            if role == "assistant":
                parts.append(f"<｜Assistant｜>{text}<｜end of sentence｜>")
            elif role in ("user", "system"):
                parts.append(text if i == 0 else f"<｜User｜>{text}")
            else:
                parts.append(text)

        result = "".join(parts)
        # Strip image markdown
        result = re.sub(r"!\[.*?\]\(.*?\)", "", result)
        return result

    # ------------------------------------------------------------------
    # Send events (reduces ban risk)
    # ------------------------------------------------------------------

    async def send_events(self, session_id: str, refresh_token: str) -> None:
        """Fire-and-forget: send fake browser events to DeepSeek."""
        try:
            token = await self.acquire_token(refresh_token)
            fake_session = f"session_v0_{_random_str('alphanum', 16)}"
            ts = _ms_ts()
            ip = await self.get_ip_address()
            events = self._build_events(fake_session, ts, ip, session_id)
            async with self._get_session().post(
                "https://chat.deepseek.com/api/v0/events",
                json={"events": events},
                headers={
                    "Authorization": f"Bearer {token}",
                    **_FAKE_HEADERS,
                    "Referer": f"https://chat.deepseek.com/a/chat/s/{session_id}",
                    "Cookie": _cookie(),
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json(content_type=None)
            self._check_result(data, refresh_token)
            logger.info("[deepseek-free-api] Events sent successfully")
        except Exception as exc:
            logger.warning(f"[deepseek-free-api] send_events failed: {exc}")

    def _build_events(
        self, fake_session: str, ts: int, ip: str, ref_conv: str
    ) -> list[dict]:
        commit_id = self._event_commit_id
        app_version = _FAKE_HEADERS["X-App-Version"]
        user_agent = _FAKE_HEADERS["User-Agent"]

        def base_payload(extra: dict | None = None) -> dict:
            p = {
                "__location": "https://chat.deepseek.com/",
                "__ip": ip,
                "__region": "CN",
                "__pageVisibility": "true",
                "__nodeEnv": "production",
                "__deployEnv": "production",
                "__appVersion": app_version,
                "__commitId": commit_id,
                "__userAgent": user_agent,
                "__referrer": "",
            }
            if extra:
                p.update(extra)
            return p

        rand_ms = lambda: random.randint(0, 999)  # noqa: E731 – local inline helper
        return [
            {
                "session_id": fake_session,
                "client_timestamp_ms": ts,
                "event_name": "__reportEvent",
                "event_message": "调用上报事件接口",
                "payload": base_payload(
                    {"method": "post", "url": "/api/v0/events", "path": "/api/v0/events"}
                ),
                "level": "info",
            },
            {
                "session_id": fake_session,
                "client_timestamp_ms": ts + 100 + rand_ms(),
                "event_name": "__reportEventOk",
                "event_message": "调用上报事件接口成功",
                "payload": base_payload(
                    {
                        "method": "post",
                        "url": "/api/v0/events",
                        "path": "/api/v0/events",
                        "logId": _new_uuid(),
                        "metricDuration": rand_ms(),
                        "status": "200",
                    }
                ),
                "level": "info",
            },
            {
                "session_id": fake_session,
                "client_timestamp_ms": ts + 200 + rand_ms(),
                "event_name": "createSessionAndStartCompletion",
                "event_message": "开始创建对话",
                "payload": base_payload(
                    {"agentId": "chat", "thinkingEnabled": False}
                ),
                "level": "info",
            },
            {
                "session_id": fake_session,
                "client_timestamp_ms": ts + 300 + rand_ms(),
                "event_name": "__httpRequest",
                "event_message": "httpRequest POST /api/v0/chat_session/create",
                "payload": base_payload(
                    {
                        "url": "/api/v0/chat_session/create",
                        "path": "/api/v0/chat_session/create",
                        "method": "POST",
                    }
                ),
                "level": "info",
            },
            {
                "session_id": fake_session,
                "client_timestamp_ms": ts + 400 + rand_ms(),
                "event_name": "__httpResponse",
                "event_message": "httpResponse POST /api/v0/chat_session/create, done",
                "payload": base_payload(
                    {
                        "url": "/api/v0/chat_session/create",
                        "path": "/api/v0/chat_session/create",
                        "method": "POST",
                        "metricDuration": rand_ms(),
                        "status": "200",
                        "logId": _new_uuid(),
                    }
                ),
                "level": "info",
            },
            {
                "session_id": fake_session,
                "client_timestamp_ms": ts + 500 + rand_ms(),
                "event_name": "completionApiOk",
                "event_message": "完成响应，响应有正常的 finish reason",
                "payload": base_payload(
                    {
                        "__location": f"https://chat.deepseek.com/a/chat/s/{ref_conv}",
                        "condition": "hasDone",
                        "streamClosed": False,
                        "scene": "completion",
                        "chatSessionId": ref_conv,
                    }
                ),
                "level": "info",
            },
        ]

    # ------------------------------------------------------------------
    # Auto version update
    # ------------------------------------------------------------------

    async def auto_update_version(self) -> None:
        """Fetch the latest commit-id and version info from DeepSeek's site."""
        try:
            async with self._get_session().get(
                "https://chat.deepseek.com/",
                headers=_FAKE_HEADERS,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                html = await resp.text()

            match = re.search(r'<meta name="commit-id" content="(.*?)">', html)
            if match:
                self._event_commit_id = match.group(1)
                logger.info(
                    f"[deepseek-free-api] commit-id updated: {self._event_commit_id}"
                )

            # Try to extract app/client version from the main JS bundle
            js_match = re.search(r'src="([^"]*?main\.[a-z0-9]+\.js)"', html, re.IGNORECASE)
            if js_match:
                js_url = js_match.group(1)
                if not js_url.startswith("http"):
                    js_url = f"https://chat.deepseek.com{js_url}"
                async with self._get_session().get(
                    js_url,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as js_resp:
                    js = await js_resp.text()
                av = re.search(r'appVersion\s*:\s*["\']([^"\']+)["\']', js, re.IGNORECASE)
                if av:
                    _FAKE_HEADERS["X-App-Version"] = av.group(1)
                cv = re.search(
                    r'clientVersion\s*:\s*["\']([^"\']+)["\']', js, re.IGNORECASE
                )
                if cv:
                    _FAKE_HEADERS["X-Client-Version"] = cv.group(1)
        except Exception as exc:
            logger.warning(f"[deepseek-free-api] auto_update_version failed: {exc}")

    # ------------------------------------------------------------------
    # Token split helper
    # ------------------------------------------------------------------

    @staticmethod
    def token_split(authorization: str) -> list[str]:
        return authorization.replace("Bearer ", "").split(",")

    # ------------------------------------------------------------------
    # Token liveness
    # ------------------------------------------------------------------

    async def get_token_live_status(self, refresh_token: str) -> bool:
        try:
            token = await self.acquire_token(refresh_token)
            async with self._get_session().get(
                "https://chat.deepseek.com/api/v0/users/current",
                headers={
                    "Authorization": f"Bearer {token}",
                    **_FAKE_HEADERS,
                    "Cookie": _cookie(),
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json(content_type=None)
            biz = self._check_result(data, refresh_token)
            return bool(biz.get("token"))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Core: non-streaming completion
    # ------------------------------------------------------------------

    async def create_completion(
        self,
        model: str,
        messages: list[dict],
        refresh_token: str,
        ref_conv_id: Optional[str] = None,
        retry: int = 0,
    ) -> dict:
        """Return a full (non-streaming) chat completion dict."""
        try:
            if not self.valid_conv_id(ref_conv_id):
                ref_conv_id = None

            prompt = (
                self.messages_prepare([messages[-1]])
                if ref_conv_id
                else self.messages_prepare(messages)
            )

            ref_session_id, ref_parent_msg_id = self._parse_conv_id(ref_conv_id)

            is_thinking = self._is_thinking(model, prompt)
            is_search = "search" in model
            is_expert = "expert" in model
            is_silent = "silent" in model
            is_fold = "fold" in model

            if is_thinking and (await self.get_thinking_quota(refresh_token)) <= 0:
                raise RuntimeError("Deep-thinking quota exhausted")

            pow_header = await self.get_pow_header(
                refresh_token, "/api/v0/chat/completion"
            )
            logger.info(f"[deepseek-free-api] PoW response (non-stream): {pow_header[:40]}…")

            token = await self.acquire_token(refresh_token)
            session_id = ref_session_id or await self.create_session(refresh_token)

            payload = {
                "chat_session_id": session_id,
                "parent_message_id": int(ref_parent_msg_id) if ref_parent_msg_id else None,
                "model_type": "expert" if is_expert else "default",
                "prompt": prompt,
                "ref_file_ids": [],
                "thinking_enabled": is_thinking,
                "search_enabled": is_search,
                "preempt": False,
            }
            async with self._get_session().post(
                "https://chat.deepseek.com/api/v0/chat/completion",
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    **_FAKE_HEADERS,
                    "Cookie": _cookie(),
                    "X-Ds-Pow-Response": pow_header,
                },
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                ct = resp.headers.get("content-type", "")
                if "text/event-stream" not in ct:
                    body = await resp.text()
                    logger.error(f"[deepseek-free-api] Unexpected content-type: {ct}\n{body[:200]}")
                    raise RuntimeError(f"Stream response Content-Type invalid: {ct}")
                result = await self._receive_stream(model, resp.content, session_id)

            asyncio.create_task(self.send_events(session_id, refresh_token))
            return result

        except Exception as exc:
            if retry < _MAX_RETRY:
                logger.warning(
                    f"[deepseek-free-api] create_completion error, retry {retry + 1}: {exc}"
                )
                await asyncio.sleep(_RETRY_DELAY)
                return await self.create_completion(
                    model, messages, refresh_token, ref_conv_id, retry + 1
                )
            raise

    # ------------------------------------------------------------------
    # Core: streaming completion
    # ------------------------------------------------------------------

    async def create_completion_stream(
        self,
        model: str,
        messages: list[dict],
        refresh_token: str,
        ref_conv_id: Optional[str] = None,
        retry: int = 0,
    ) -> AsyncGenerator[bytes, None]:
        """Yield SSE bytes in OpenAI-compatible format."""
        try:
            if not self.valid_conv_id(ref_conv_id):
                ref_conv_id = None

            prompt = (
                self.messages_prepare([messages[-1]])
                if ref_conv_id
                else self.messages_prepare(messages)
            )

            ref_session_id, ref_parent_msg_id = self._parse_conv_id(ref_conv_id)

            is_thinking = self._is_thinking(model, prompt)
            is_search = "search" in model
            is_expert = "expert" in model
            is_silent = "silent" in model
            is_fold = "fold" in model
            is_search_silent = "search-silent" in model

            if is_thinking and (await self.get_thinking_quota(refresh_token)) <= 0:
                raise RuntimeError("Deep-thinking quota exhausted")

            pow_header = await self.get_pow_header(
                refresh_token, "/api/v0/chat/completion"
            )

            token = await self.acquire_token(refresh_token)
            session_id = ref_session_id or await self.create_session(refresh_token)

            payload = {
                "chat_session_id": session_id,
                "parent_message_id": int(ref_parent_msg_id) if ref_parent_msg_id else None,
                "model_type": "expert" if is_expert else "default",
                "prompt": prompt,
                "ref_file_ids": [],
                "thinking_enabled": is_thinking,
                "search_enabled": is_search,
                "preempt": False,
            }
            async with self._get_session().post(
                "https://chat.deepseek.com/api/v0/chat/completion",
                json=payload,
                headers={
                    "Authorization": f"Bearer {token}",
                    **_FAKE_HEADERS,
                    "Cookie": _cookie(),
                    "X-Ds-Pow-Response": pow_header,
                },
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                asyncio.create_task(self.send_events(session_id, refresh_token))
                ct = resp.headers.get("content-type", "")
                if "text/event-stream" not in ct:
                    error_msg = (
                        "服务暂时不可用，第三方响应错误"
                    )
                    yield self.sse_chunk(
                        "",
                        model,
                        {"role": "assistant", "content": error_msg},
                        finish_reason=None,
                    )
                    yield self.sse_done_chunk("", model)
                    yield b"data: [DONE]\n\n"
                    return

                async for chunk in self._transform_stream(
                    model, resp.content, session_id, is_thinking,
                    is_silent, is_fold, is_search_silent
                ):
                    yield chunk

        except Exception as exc:
            if retry < _MAX_RETRY:
                logger.warning(
                    f"[deepseek-free-api] create_completion_stream error, retry {retry + 1}: {exc}"
                )
                await asyncio.sleep(_RETRY_DELAY)
                async for chunk in self.create_completion_stream(
                    model, messages, refresh_token, ref_conv_id, retry + 1
                ):
                    yield chunk
            else:
                raise

    # ------------------------------------------------------------------
    # Stream helpers
    # ------------------------------------------------------------------

    async def _receive_stream(
        self, model: str, stream: aiohttp.StreamReader, session_id: str
    ) -> dict:
        """Consume SSE stream and return a complete chat completion dict."""
        is_thinking = "think" in model or "r1" in model
        accumulated = ""
        accumulated_thinking = ""
        message_id = ""
        current_path = "thinking" if is_thinking else "content"
        created = _unix_ts()

        buf = ""
        async for raw_line in stream:
            line = raw_line.decode(errors="replace")
            buf += line
            # Process complete SSE events from buf
            while "\n\n" in buf:
                event_raw, buf = buf.split("\n\n", 1)
                for ev_line in event_raw.split("\n"):
                    ev_line = ev_line.strip()
                    if ev_line.startswith("data:"):
                        data_str = ev_line[5:].strip()
                        if data_str == "[DONE]":
                            continue
                        try:
                            chunk = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue
                        if chunk.get("response_message_id") and not message_id:
                            message_id = chunk["response_message_id"]
                        p = chunk.get("p", "")
                        v = chunk.get("v")
                        if p:
                            if "fragments" in p and isinstance(v, list) and v:
                                ftype = v[0].get("type")
                                if ftype == "THINK":
                                    current_path = "thinking"
                                elif ftype == "RESPONSE":
                                    current_path = "content"
                            elif "thinking_content" in p or "thought" in p:
                                current_path = "thinking"
                            elif "response/content" in p:
                                current_path = "content"
                        if isinstance(v, str) and v != "FINISHED":
                            if current_path == "thinking":
                                accumulated_thinking += v
                            else:
                                accumulated += v

        return {
            "id": f"{session_id}@{message_id}",
            "model": model,
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": accumulated.strip(),
                        "reasoning_content": accumulated_thinking.strip(),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            "created": created,
        }

    async def _transform_stream(
        self,
        model: str,
        stream: aiohttp.StreamReader,
        session_id: str,
        is_thinking: bool,
        is_silent: bool,
        is_fold: bool,
        is_search_silent: bool,
    ) -> AsyncGenerator[bytes, None]:
        """Yield OpenAI-format SSE bytes from a raw DeepSeek stream."""
        current_path = "thinking" if is_thinking else "content"
        search_results: list[dict] = []
        thinking_started = False
        is_first_chunk = True
        message_id = ""
        created = _unix_ts()

        buf = ""
        async for raw_line in stream:
            line = raw_line.decode(errors="replace")
            buf += line
            while "\n\n" in buf:
                event_raw, buf = buf.split("\n\n", 1)
                for ev_line in event_raw.split("\n"):
                    ev_line = ev_line.strip()
                    if not ev_line.startswith("data:"):
                        continue
                    data_str = ev_line[5:].strip()

                    if data_str == "[DONE]":
                        # Finalize fold tag
                        if is_fold and thinking_started:
                            yield self.sse_chunk(
                                f"{session_id}@{message_id}",
                                model,
                                {"content": "</pre></details>"},
                            )
                        # Append search citations
                        citations_text = self._build_citations(
                            search_results, is_search_silent
                        )
                        if citations_text:
                            yield self.sse_chunk(
                                f"{session_id}@{message_id}",
                                model,
                                {"content": citations_text},
                            )
                        yield self.sse_done_chunk(
                            f"{session_id}@{message_id}", model
                        )
                        yield b"data: [DONE]\n\n"
                        return

                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    if chunk.get("response_message_id") and not message_id:
                        message_id = str(chunk["response_message_id"])

                    p = chunk.get("p", "")
                    v = chunk.get("v")
                    o = chunk.get("o", "")

                    # Update current path
                    if p:
                        if "fragments" in p and isinstance(v, list) and v:
                            ftype = v[0].get("type")
                            if ftype == "THINK":
                                current_path = "thinking"
                            elif ftype == "RESPONSE":
                                current_path = "content"
                        elif "thinking_content" in p or "thought" in p:
                            current_path = "thinking"
                        elif "response/content" in p:
                            current_path = "content"

                    # Search results
                    is_search_path = (
                        p == "response/search_results"
                        or (p and p.endswith("/results") and "fragments" in p)
                    )
                    if is_search_path and isinstance(v, list):
                        if o == "BATCH":
                            for op in v:
                                match = re.search(r"/(\d+)/(\w+)$", op.get("p", ""))
                                if match:
                                    idx = int(match.group(1))
                                    key = match.group(2)
                                    while len(search_results) <= idx:
                                        search_results.append({})
                                    search_results[idx][key] = op.get("v")
                        else:
                            search_results.extend(v)
                        continue

                    # Content / thinking
                    is_content_path = (
                        not p or "content" in p or "thought" in p
                    )
                    if (
                        isinstance(v, str)
                        and v != "FINISHED"
                        and v != "SEARCH"
                        and is_content_path
                    ):
                        delta: dict = {}
                        if is_first_chunk:
                            delta["role"] = "assistant"
                            is_first_chunk = False

                        content = (
                            re.sub(r"\[citation:(\d+)\]", "", v)
                            if is_search_silent
                            else re.sub(r"\[citation:(\d+)\]", r"[\1]", v)
                        )

                        if current_path == "thinking":
                            if is_silent:
                                continue
                            if is_fold:
                                if not thinking_started:
                                    thinking_started = True
                                    delta["content"] = (
                                        f"<details><summary>思考过程</summary><pre>{content}"
                                    )
                                else:
                                    delta["content"] = content
                            else:
                                delta["reasoning_content"] = content
                        else:
                            if is_fold and thinking_started:
                                delta["content"] = f"</pre></details>{content}"
                                thinking_started = False
                            else:
                                delta["content"] = content

                        if delta:
                            yield self.sse_chunk(
                                f"{session_id}@{message_id}", model, delta
                            )

        # Stream ended without [DONE]
        if is_fold and thinking_started:
            yield self.sse_chunk(
                f"{session_id}@{message_id}",
                model,
                {"content": "</pre></details>"},
            )
        citations_text = self._build_citations(search_results, is_search_silent)
        if citations_text:
            yield self.sse_chunk(
                f"{session_id}@{message_id}", model, {"content": citations_text}
            )
        yield self.sse_done_chunk(f"{session_id}@{message_id}", model)
        yield b"data: [DONE]\n\n"

    # ------------------------------------------------------------------
    # SSE formatting helpers
    # ------------------------------------------------------------------

    def sse_chunk(
        self,
        completion_id: str,
        model: str,
        delta: dict,
        finish_reason: Optional[str] = None,
    ) -> bytes:
        payload = {
            "id": completion_id,
            "model": model,
            "object": "chat.completion.chunk",
            "choices": [
                {"index": 0, "delta": delta, "finish_reason": finish_reason}
            ],
            "created": _unix_ts(),
        }
        return f"data: {json.dumps(payload)}\n\n".encode()

    def sse_done_chunk(self, completion_id: str, model: str) -> bytes:
        return self.sse_chunk(
            completion_id, model, {}, finish_reason="stop"
        )

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    @staticmethod
    def valid_conv_id(conv_id: Optional[str]) -> bool:
        if not conv_id:
            return False
        return bool(re.match(r"[0-9a-z\-]{36}@\d+", conv_id))

    @staticmethod
    def _parse_conv_id(conv_id: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        if not conv_id:
            return None, None
        parts = conv_id.split("@", 1)
        return parts[0], parts[1] if len(parts) > 1 else None

    @staticmethod
    def _is_thinking(model: str, prompt: str) -> bool:
        return (
            "think" in model
            or "r1" in model
            or "深度思考" in prompt
            or prompt.startswith("?")
            or prompt.startswith("？")
        )

    @staticmethod
    def _build_citations(
        search_results: list[dict], is_search_silent: bool
    ) -> str:
        if not search_results or is_search_silent:
            return ""
        lines = [
            f"**{r['cite_index']}.** [{r.get('title', '')}]({r.get('url', '')})"
            for r in sorted(search_results, key=lambda x: x.get("cite_index", 0))
            if r.get("cite_index")
        ]
        return f"\n\n**Citations:**\n" + "\n".join(lines) if lines else ""


# ---------------------------------------------------------------------------
# UMO–ConvID persistence (SQLite)
# ---------------------------------------------------------------------------


class ConvIdStore:
    """Persists unified_msg_origin → DeepSeek conversation_id mappings."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS umo_conv (
                    umo      TEXT PRIMARY KEY,
                    conv_id  TEXT NOT NULL,
                    updated  INTEGER NOT NULL
                )
                """
            )
            conn.commit()

    def get(self, umo: str) -> Optional[str]:
        with sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT conv_id FROM umo_conv WHERE umo = ?", (umo,)
            ).fetchone()
        return row[0] if row else None

    def set(self, umo: str, conv_id: str) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT INTO umo_conv (umo, conv_id, updated)
                VALUES (?, ?, ?)
                ON CONFLICT(umo) DO UPDATE SET conv_id=excluded.conv_id,
                                               updated=excluded.updated
                """,
                (umo, conv_id, _unix_ts()),
            )
            conn.commit()


# ---------------------------------------------------------------------------
# AstrBot Plugin
# ---------------------------------------------------------------------------


class DeepSeekFreeAPI(star.Star):
    """
    AstrBot plugin: Deepseek Free API

    Starts a local OpenAI-compatible HTTP server that proxies to DeepSeek's
    web API.  When AstrBot itself is the client (signalled by the configured
    client_identifier in the Authorization header), the plugin tracks
    DeepSeek session continuity per AstrBot conversation (UMO).
    """

    def __init__(self, context: Context, config: AstrBotConfig = None) -> None:
        super().__init__(context)
        cfg = config or {}

        self._port: int = int(cfg.get("port", 5566))
        self._client_identifier: str = str(cfg.get("client_identifier", ""))
        self._deepseek_token: str = str(cfg.get("deepseek_token", ""))

        self._ds_client = DeepSeekClient()

        # Pending nonce map: nonce (str) → {"umo": str, "conv_id": str|None}
        self._pending: dict[str, dict] = {}

        # Persistence
        data_dir = get_astrbot_data_path() or os.path.join(
            os.path.dirname(__file__), "data"
        )
        plugin_data_dir = os.path.join(data_dir, "plugin_data", "deepseek_free_api")
        os.makedirs(plugin_data_dir, exist_ok=True)
        self._store = ConvIdStore(
            os.path.join(plugin_data_dir, "umo_conv.db")
        )

        # aiohttp runner
        self._runner: web.AppRunner | None = None
        self._version_update_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Called by AstrBot after handler binding; starts the HTTP server."""
        # Register plugin config items in AstrBot's config system (shown in WebUI)
        _PLUGIN_NS = "deepseek-free-api"
        try:
            put_config(
                _PLUGIN_NS,
                "服务端口",
                "port",
                self._port,
                "本地 OpenAI 兼容 HTTP 服务器的监听端口（默认 5566）",
            )
            put_config(
                _PLUGIN_NS,
                "客户端标识",
                "client_identifier",
                self._client_identifier,
                (
                    "当请求的 Authorization 头包含此字符串时，启用 AstrBot 会话"
                    "（unified_msg_origin）与 DeepSeek 云端上下文的绑定。"
                    "留空则不启用该功能。"
                ),
            )
            put_config(
                _PLUGIN_NS,
                "DeepSeek Token（可选）",
                "deepseek_token",
                self._deepseek_token,
                (
                    "可选：插件级别的 DeepSeek refresh_token，覆盖请求中的"
                    " Authorization 头。留空则使用请求方自带的 token。"
                ),
            )
        except Exception as exc:
            logger.warning(f"[deepseek-free-api] put_config failed: {exc}")

        await self._start_server()
        # Kick off periodic version updates (every 10 minutes)
        self._version_update_task = asyncio.create_task(
            self._version_update_loop()
        )
        logger.info(
            f"[deepseek-free-api] Plugin ready – server on port {self._port}"
        )

    async def terminate(self) -> None:
        """Called by AstrBot on plugin unload; shuts down gracefully."""
        if self._version_update_task:
            self._version_update_task.cancel()
        if self._runner:
            await self._runner.cleanup()
        await self._ds_client.close()
        logger.info("[deepseek-free-api] Plugin stopped")

    # ------------------------------------------------------------------
    # AstrBot LLM request hook
    # ------------------------------------------------------------------

    @event_filter.on_llm_request()
    async def on_llm_request(
        self, event: AstrMessageEvent, req: ProviderRequest
    ) -> None:
        """
        Intercept outgoing LLM requests from AstrBot.

        When the client_identifier is configured, inject a unique nonce into
        the system_prompt.  The local HTTP server will look up the nonce to
        retrieve the UMO and associated DeepSeek conversation_id, enabling
        cloud-context continuity across turns.
        """
        if not self._client_identifier:
            return

        try:
            umo: str = getattr(event, "unified_msg_origin", "") or ""
            if not umo:
                return
            conv_id: Optional[str] = self._store.get(umo)
            nonce = _new_uuid(sep=False)
            self._pending[nonce] = {"umo": umo, "conv_id": conv_id}

            marker = f"{_NONCE_MARKER_PREFIX}{nonce}{_NONCE_MARKER_SUFFIX}"
            req.system_prompt = marker + ("\n" + req.system_prompt if req.system_prompt else "")
        except Exception as exc:
            logger.warning(f"[deepseek-free-api] on_llm_request hook error: {exc}")

    # ------------------------------------------------------------------
    # HTTP server
    # ------------------------------------------------------------------

    async def _start_server(self) -> None:
        app = web.Application()
        app.router.add_get("/", self._handle_root)
        app.router.add_get("/ping", self._handle_ping)
        app.router.add_get("/v1/models", self._handle_models)
        app.router.add_post("/v1/chat/completions", self._handle_chat_completions)
        app.router.add_post("/token/check", self._handle_token_check)
        # Store plugin reference on app for handler access
        app["plugin"] = self
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        logger.info(
            f"[deepseek-free-api] HTTP server listening on 0.0.0.0:{self._port}"
        )

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    async def _handle_root(self, request: web.Request) -> web.Response:
        html = (
            "<html><body>"
            "<h2>Deepseek Free API (AstrBot Plugin)</h2>"
            "<p>POST /v1/chat/completions</p>"
            "<p>GET  /v1/models</p>"
            "<p>POST /token/check</p>"
            "</body></html>"
        )
        return web.Response(text=html, content_type="text/html")

    async def _handle_ping(self, request: web.Request) -> web.Response:
        return web.Response(text="pong")

    async def _handle_models(self, request: web.Request) -> web.Response:
        models = [
            "deepseek",
            "deepseek-chat",
            "deepseek-think",
            "deepseek-r1",
            "deepseek-search",
            "deepseek-expert",
            "deepseek-expert-r1",
            "deepseek-expert-search",
            "deepseek-expert-r1-search",
            "deepseek-r1-search",
            "deepseek-think-search",
            "deepseek-r1-silent",
            "deepseek-search-silent",
            "deepseek-think-fold",
            "deepseek-r1-fold",
        ]
        data = [
            {"id": m, "object": "model", "owned_by": "deepseek-free-api"}
            for m in models
        ]
        return web.json_response({"data": data})

    async def _handle_token_check(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"error": "invalid JSON body"}, status=400
            )
        token = body.get("token", "")
        if not token:
            return web.json_response(
                {"error": "token field is required"}, status=400
            )
        live = await self._ds_client.get_token_live_status(token)
        return web.json_response({"live": live})

    async def _handle_chat_completions(
        self, request: web.Request
    ) -> web.Response | web.StreamResponse:
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"error": "invalid JSON body"}, status=400
            )

        # ------------------------------------------------------------------
        # Resolve authorization / token
        # ------------------------------------------------------------------
        authorization = request.headers.get("Authorization", "")
        if self._deepseek_token:
            # Plugin-level override
            authorization = f"Bearer {self._deepseek_token}"
        if not authorization:
            return web.json_response(
                {"error": "Authorization header is required"}, status=401
            )

        tokens = self._ds_client.token_split(authorization)
        refresh_token = random.choice(tokens)

        # ------------------------------------------------------------------
        # UMO / conversation-id resolution (AstrBot-sourced requests only)
        # ------------------------------------------------------------------
        conv_id: Optional[str] = body.get("conversation_id")
        umo: Optional[str] = None

        # Detect AstrBot-sourced requests via a dedicated header
        astrbot_header = request.headers.get("X-from-which-astrbot", "")
        if self._client_identifier and astrbot_header and self._client_identifier in astrbot_header:
            # This request came from AstrBot; extract the nonce marker
            for msg in body.get("messages", []):
                if msg.get("role") == "system":
                    content = msg.get("content", "")
                    nonce_match = re.search(
                        re.escape(_NONCE_MARKER_PREFIX)
                        + r"([0-9a-f]+)"
                        + re.escape(_NONCE_MARKER_SUFFIX),
                        content,
                    )
                    if nonce_match:
                        nonce = nonce_match.group(1)
                        pending = self._pending.pop(nonce, None)
                        if pending:
                            umo = pending["umo"]
                            # Use stored conv_id from DB if caller didn't
                            # supply one (or supplied an invalid one)
                            if not self._ds_client.valid_conv_id(conv_id):
                                conv_id = pending["conv_id"]
                    # Strip the nonce marker so DeepSeek doesn't see it
                    msg["content"] = re.sub(
                        re.escape(_NONCE_MARKER_PREFIX)
                        + r"[0-9a-f]+"
                        + re.escape(_NONCE_MARKER_SUFFIX)
                        + r"\n?",
                        "",
                        content,
                    ).strip()
                break

        model = str(body.get("model", _MODEL_NAME)).lower()
        messages: list[dict] = body.get("messages", [])
        stream: bool = bool(body.get("stream", False))

        if not messages:
            return web.json_response(
                {"error": "messages field is required"}, status=400
            )

        # ------------------------------------------------------------------
        # Streaming response
        # ------------------------------------------------------------------
        if stream:
            sr = web.StreamResponse(
                headers={
                    "Content-Type": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Access-Control-Allow-Origin": "*",
                }
            )
            await sr.prepare(request)
            new_conv_id: Optional[str] = None
            try:
                async for chunk in self._ds_client.create_completion_stream(
                    model, messages, refresh_token, conv_id
                ):
                    await sr.write(chunk)
                    # Capture the completion_id from the first content chunk
                    if new_conv_id is None and chunk.startswith(b"data:"):
                        try:
                            evt = json.loads(chunk[5:].strip())
                            cid = evt.get("id", "")
                            if self._ds_client.valid_conv_id(cid):
                                new_conv_id = cid
                        except Exception:
                            pass
            except Exception as exc:
                logger.error(f"[deepseek-free-api] stream error: {exc}")
                err_chunk = self._ds_client.sse_chunk(
                    "", model, {"content": f"Error: {exc}"}, finish_reason="stop"
                )
                await sr.write(err_chunk)
                await sr.write(b"data: [DONE]\n\n")
            finally:
                await sr.write_eof()
                if umo and new_conv_id:
                    self._store.set(umo, new_conv_id)
            return sr

        # ------------------------------------------------------------------
        # Non-streaming response
        # ------------------------------------------------------------------
        try:
            result = await self._ds_client.create_completion(
                model, messages, refresh_token, conv_id
            )
        except Exception as exc:
            logger.error(f"[deepseek-free-api] completion error: {exc}")
            return web.json_response({"error": str(exc)}, status=500)

        # Update UMO→conv_id mapping
        if umo:
            new_cid = result.get("id", "")
            if self._ds_client.valid_conv_id(new_cid):
                self._store.set(umo, new_cid)

        return web.json_response(result)

    # ------------------------------------------------------------------
    # Periodic version update loop
    # ------------------------------------------------------------------

    async def _version_update_loop(self) -> None:
        # Initial update after a short delay
        await asyncio.sleep(5)
        while True:
            await self._ds_client.auto_update_version()
            await asyncio.sleep(600)  # every 10 minutes
