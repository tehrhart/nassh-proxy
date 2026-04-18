"""Identity provider abstraction. Backends: Cloudflare Access, GCP IAP, none."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Mapping

import jwt
from jwt import PyJWKClient


@dataclass(frozen=True)
class Identity:
    provider: str
    sub: str | None = None
    email: str | None = None
    claims: Mapping[str, Any] = field(default_factory=dict)

    @property
    def principal(self) -> str | None:
        return self.email or self.sub


class IdentityProvider(ABC):
    name: str

    @abstractmethod
    def identify(self, headers: Mapping[str, str]) -> Identity | None:
        """Return Identity for an authenticated request, or None if auth not required and absent.

        Raises PermissionError when auth is required and the token is missing or invalid.
        """


class NoneProvider(IdentityProvider):
    name = "none"

    def identify(self, headers):
        return None


class CloudflareAccessProvider(IdentityProvider):
    name = "cloudflare-access"

    def __init__(self, team_domain: str, audience: str, required: bool = True):
        self.issuer = f"https://{team_domain}.cloudflareaccess.com"
        self.audience = audience
        self.required = required
        self._jwks = PyJWKClient(f"{self.issuer}/cdn-cgi/access/certs")

    def identify(self, headers):
        token = headers.get("cf-access-jwt-assertion")
        if not token:
            token = _cookie(headers.get("cookie", ""), "CF_Authorization")
        if not token:
            if self.required:
                raise PermissionError("missing Cloudflare Access assertion")
            return None
        key = self._jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        return Identity(
            provider=self.name,
            sub=claims.get("sub"),
            email=claims.get("email"),
            claims=claims,
        )


class GcpIapProvider(IdentityProvider):
    name = "gcp-iap"

    def __init__(self, audience: str, required: bool = True):
        self.audience = audience
        self.required = required
        self.issuer = "https://cloud.google.com/iap"
        self._jwks = PyJWKClient("https://www.gstatic.com/iap/verify/public_key-jwk")

    def identify(self, headers):
        token = headers.get("x-goog-iap-jwt-assertion")
        if not token:
            if self.required:
                raise PermissionError("missing GCP IAP assertion")
            return None
        key = self._jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        # IAP puts the stable user id in "sub" and email in "email".
        return Identity(
            provider=self.name,
            sub=claims.get("sub"),
            email=claims.get("email"),
            claims=claims,
        )


def build_provider(kind: str, **kwargs) -> IdentityProvider:
    kind = kind.lower()
    if kind in ("none", "disabled", ""):
        return NoneProvider()
    if kind == "cloudflare-access":
        return CloudflareAccessProvider(
            team_domain=kwargs["team_domain"],
            audience=kwargs["audience"],
            required=kwargs.get("required", True),
        )
    if kind == "gcp-iap":
        return GcpIapProvider(
            audience=kwargs["audience"],
            required=kwargs.get("required", True),
        )
    raise ValueError(f"unknown identity provider: {kind}")


def _cookie(header: str, name: str) -> str | None:
    for part in header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return None
