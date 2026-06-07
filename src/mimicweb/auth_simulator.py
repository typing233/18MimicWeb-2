"""OAuth2 and JWT simulation for convincing honeypot authentication flows."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any

import jwt
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse


_JWT_SECRET = secrets.token_hex(32)
_AUTH_CODES: dict[str, dict[str, Any]] = {}
_REFRESH_TOKENS: dict[str, dict[str, Any]] = {}


class AuthSimulator:
    def __init__(self, issuer: str = "https://auth.corp.internal"):
        self._issuer = issuer
        self._jwt_secret = _JWT_SECRET

    def get_routes(self) -> list[dict[str, Any]]:
        return [
            {"path": "/oauth/authorize", "method": "GET", "handler": self.authorize},
            {"path": "/oauth/token", "method": "POST", "handler": self.token},
            {"path": "/oauth/userinfo", "method": "GET", "handler": self.userinfo},
            {"path": "/.well-known/openid-configuration", "method": "GET", "handler": self.openid_config},
            {"path": "/.well-known/jwks.json", "method": "GET", "handler": self.jwks},
            {"path": "/api/auth/login", "method": "POST", "handler": self.login},
        ]

    async def authorize(self, request: Request) -> Any:
        client_id = request.query_params.get("client_id", "unknown")
        redirect_uri = request.query_params.get("redirect_uri", "/callback")
        state = request.query_params.get("state", "")
        scope = request.query_params.get("scope", "openid profile")

        code = secrets.token_urlsafe(32)
        _AUTH_CODES[code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "created_at": time.time(),
            "user_id": str(uuid.uuid4()),
        }

        separator = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{separator}code={code}"
        if state:
            location += f"&state={state}"

        return RedirectResponse(url=location, status_code=302)

    async def token(self, request: Request) -> JSONResponse:
        try:
            body = await request.body()
            if request.headers.get("content-type", "").startswith("application/json"):
                data = json.loads(body)
            else:
                from urllib.parse import parse_qs
                parsed = parse_qs(body.decode())
                data = {k: v[0] for k, v in parsed.items()}
        except Exception:
            data = {}

        grant_type = data.get("grant_type", "")

        if grant_type == "authorization_code":
            code = data.get("code", "")
            code_data = _AUTH_CODES.pop(code, None)
            if not code_data:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
                    status_code=400,
                )
            user_id = code_data["user_id"]
            scope = code_data["scope"]

        elif grant_type == "refresh_token":
            refresh = data.get("refresh_token", "")
            token_data = _REFRESH_TOKENS.get(refresh)
            if not token_data:
                return JSONResponse(
                    {"error": "invalid_grant", "error_description": "Invalid refresh token"},
                    status_code=400,
                )
            user_id = token_data["user_id"]
            scope = token_data["scope"]

        elif grant_type == "client_credentials":
            user_id = data.get("client_id", "service-account")
            scope = data.get("scope", "api.read")

        else:
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=400,
            )

        now = int(time.time())
        access_token = self._sign_jwt({
            "sub": user_id,
            "iss": self._issuer,
            "aud": data.get("client_id", "default"),
            "iat": now,
            "exp": now + 3600,
            "scope": scope,
            "jti": str(uuid.uuid4()),
        })

        refresh_token = secrets.token_urlsafe(48)
        _REFRESH_TOKENS[refresh_token] = {
            "user_id": user_id,
            "scope": scope,
            "created_at": now,
        }

        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": scope,
        })

    async def userinfo(self, request: Request) -> JSONResponse:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "invalid_token"}, status_code=401)

        token = auth_header[7:]
        try:
            payload = jwt.decode(token, self._jwt_secret, algorithms=["HS256"],
                                 options={"verify_aud": False})
        except jwt.ExpiredSignatureError:
            return JSONResponse({"error": "token_expired"}, status_code=401)
        except jwt.InvalidTokenError:
            return JSONResponse({"error": "invalid_token"}, status_code=401)

        return JSONResponse({
            "sub": payload.get("sub"),
            "name": f"User {payload.get('sub', '')[:8]}",
            "email": f"{payload.get('sub', 'user')[:8]}@corp.internal",
            "email_verified": True,
            "updated_at": int(time.time()),
        })

    async def openid_config(self, request: Request) -> JSONResponse:
        base = self._issuer
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "userinfo_endpoint": f"{base}/oauth/userinfo",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256"],
            "scopes_supported": ["openid", "profile", "email", "api.read", "api.write"],
        })

    async def jwks(self, request: Request) -> JSONResponse:
        kid = hashlib.sha256(self._jwt_secret.encode()).hexdigest()[:16]
        return JSONResponse({
            "keys": [{
                "kty": "oct",
                "kid": kid,
                "use": "sig",
                "alg": "HS256",
            }]
        })

    async def login(self, request: Request) -> JSONResponse:
        try:
            body = await request.body()
            content_type = request.headers.get("content-type", "")
            if "json" in content_type:
                data = json.loads(body)
            else:
                from urllib.parse import parse_qs
                parsed = parse_qs(body.decode())
                data = {k: v[0] for k, v in parsed.items()}
        except Exception:
            data = {}

        username = data.get("username", "")
        now = int(time.time())

        access_token = self._sign_jwt({
            "sub": username or "anonymous",
            "iss": self._issuer,
            "iat": now,
            "exp": now + 3600,
            "role": "user",
        })

        return JSONResponse({
            "success": True,
            "user": {
                "username": username,
                "id": str(uuid.uuid4()),
                "role": "user",
            },
            "token": access_token,
            "expires_in": 3600,
        })

    def _sign_jwt(self, payload: dict[str, Any]) -> str:
        return jwt.encode(payload, self._jwt_secret, algorithm="HS256")
