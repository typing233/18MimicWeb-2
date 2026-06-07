"""Tests for OAuth2/JWT authentication simulation."""

import json
import time

import jwt
import pytest
from starlette.testclient import TestClient

from mimicweb.main import build_app


@pytest.fixture
def client(config_file):
    app = build_app(config_file)
    return TestClient(app, follow_redirects=False)


class TestOAuth2Flow:
    def test_authorize_redirects(self, client):
        resp = client.get("/oauth/authorize", params={
            "client_id": "test-app",
            "redirect_uri": "http://localhost/callback",
            "state": "xyz",
            "scope": "openid profile",
        })
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "code=" in location
        assert "state=xyz" in location

    def test_token_exchange(self, client):
        # Get auth code
        resp = client.get("/oauth/authorize", params={
            "client_id": "test-app",
            "redirect_uri": "http://localhost/callback",
        })
        location = resp.headers["location"]
        code = location.split("code=")[1].split("&")[0]

        # Exchange for token
        resp = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "test-app",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert "refresh_token" in data
        assert data["expires_in"] == 3600

    def test_invalid_code(self, client):
        resp = client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": "invalid",
        })
        assert resp.status_code == 400
        assert "invalid_grant" in resp.json()["error"]

    def test_client_credentials(self, client):
        resp = client.post("/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": "service-a",
            "scope": "api.read",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

    def test_unsupported_grant(self, client):
        resp = client.post("/oauth/token", data={
            "grant_type": "unknown",
        })
        assert resp.status_code == 400

    def test_refresh_token(self, client):
        # Get initial token
        resp = client.post("/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": "svc",
        })
        refresh = resp.json()["refresh_token"]

        # Use refresh token
        resp = client.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()


class TestJWT:
    def test_jwt_valid_structure(self, client):
        resp = client.post("/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": "test",
        })
        token = resp.json()["access_token"]
        # Decode without verification to check structure
        payload = jwt.decode(token, options={"verify_signature": False})
        assert "sub" in payload
        assert "iss" in payload
        assert "exp" in payload
        assert payload["exp"] > time.time()


class TestUserinfo:
    def test_userinfo_with_token(self, client):
        # Get token
        resp = client.post("/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": "test",
        })
        token = resp.json()["access_token"]

        resp = client.get("/oauth/userinfo", headers={
            "Authorization": f"Bearer {token}"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "sub" in data
        assert "email" in data

    def test_userinfo_no_token(self, client):
        resp = client.get("/oauth/userinfo")
        assert resp.status_code == 401


class TestLogin:
    def test_form_login(self, client):
        resp = client.post("/api/auth/login", data={
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["user"]["username"] == "admin"
        assert "token" in data


class TestOpenIDConfig:
    def test_well_known(self, client):
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        data = resp.json()
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data

    def test_jwks(self, client):
        resp = client.get("/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) > 0
