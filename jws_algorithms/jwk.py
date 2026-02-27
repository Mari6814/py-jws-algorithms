"""Converts cryptography library keys to JWK (JSON Web Key) format.

This module is **not intended** to be used directly, instead you should use the `to_jwk` method of the `AsymmetricAlgorithm` enum.

Example::

    from jws_algorithms import AsymmetricAlgorithm

    pub, pk = AsymmetricAlgorithm.ES256.generate_keypair()
    jwk = AsymmetricAlgorithm.ES256.to_jwk(pub)
    print(jwk)

"""

import base64
from typing import TypedDict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_uint(value: int) -> str:
    """Encode integer as urlsafe base64 string."""
    if not value:
        return _base64url_encode(b"\x00")
    byte_length = (value.bit_length() + 7) // 8
    return _base64url_encode(value.to_bytes(byte_length, byteorder="big"))


def _rsa_public_to_jwk(
    key: rsa.RSAPublicKey,
    alg: str,
    private_key: rsa.RSAPrivateKey | None = None,
) -> "RSAPublicJWK | RSAPrivateJWK":
    """Build a JWK dict for an RSA public key, optionally including private components."""
    numbers = key.public_numbers()
    jwk: RSAPublicJWK = {
        "kty": "RSA",
        "n": _base64url_uint(numbers.n),
        "e": _base64url_uint(numbers.e),
        "alg": alg,
        "use": "sig",
    }
    if private_key is not None:
        pn = private_key.private_numbers()
        jwk_private: RSAPrivateJWK = {
            **jwk,
            "d": _base64url_uint(pn.d),
            "p": _base64url_uint(pn.p),
            "q": _base64url_uint(pn.q),
            "dp": _base64url_uint(pn.dmp1),
            "dq": _base64url_uint(pn.dmq1),
            "qi": _base64url_uint(pn.iqmp),
        }
        return jwk_private
    return jwk


def _ec_public_to_jwk(
    key: ec.EllipticCurvePublicKey,
    alg: str,
    private_key: ec.EllipticCurvePrivateKey | None = None,
) -> "ECPublicJWK | ECPrivateJWK":
    """Build a JWK dict for an EC public key, optionally including the private scalar."""
    numbers = key.public_numbers()
    crv = {
        "secp256r1": "P-256",
        "secp384r1": "P-384",
        "secp521r1": "P-521",
    }[key.curve.name]
    coord_size = (key.curve.key_size + 7) // 8
    jwk: ECPublicJWK = {
        "kty": "EC",
        "crv": crv,
        "x": _base64url_encode(numbers.x.to_bytes(coord_size, byteorder="big")),
        "y": _base64url_encode(numbers.y.to_bytes(coord_size, byteorder="big")),
        "alg": alg,
        "use": "sig",
    }
    if private_key is not None:
        pn = private_key.private_numbers()
        jwk_private: ECPrivateJWK = {
            **jwk,
            "d": _base64url_encode(
                pn.private_value.to_bytes(coord_size, byteorder="big")
            ),
        }
        return jwk_private
    return jwk


def _okp_public_to_jwk(
    key: ed25519.Ed25519PublicKey | ed448.Ed448PublicKey,
    alg: str,
    private_key: ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey | None = None,
) -> "OKPPublicJWK | OKPPrivateJWK":
    """Build a JWK dict for an OKP (EdDSA) public key, optionally including the private scalar."""
    crv = "Ed25519" if isinstance(key, ed25519.Ed25519PublicKey) else "Ed448"
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk: OKPPublicJWK = {
        "kty": "OKP",
        "crv": crv,
        "x": _base64url_encode(raw),
        "alg": alg,
        "use": "sig",
    }
    if private_key is not None:
        raw_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        jwk_private: OKPPrivateJWK = {**jwk, "d": _base64url_encode(raw_private)}
        return jwk_private
    return jwk


class RSAPublicJWK(TypedDict):
    """JWK dict for an RSA public key, with required fields."""

    kty: str
    n: str
    e: str
    alg: str
    use: str


class RSAPrivateJWK(RSAPublicJWK, total=False):
    """JWK dict for an RSA private key, including the private components."""

    d: str
    p: str
    q: str
    dp: str
    dq: str
    qi: str


class ECPublicJWK(TypedDict):
    """JWK dict for an EC public key, with required fields."""

    kty: str
    crv: str
    x: str
    y: str
    alg: str
    use: str


class ECPrivateJWK(ECPublicJWK, total=False):
    """JWK dict for an EC private key, including the private scalar."""

    d: str


class OKPPublicJWK(TypedDict):
    """JWK dict for an OKP (EdDSA) public key, with required fields."""

    kty: str
    crv: str
    x: str
    alg: str
    use: str


class OKPPrivateJWK(OKPPublicJWK, total=False):
    """JWK dict for an OKP (EdDSA) private key, including the private scalar."""

    d: str
