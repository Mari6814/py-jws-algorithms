from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from jws_algorithms.algorithms import AsymmetricAlgorithm


def test_rsa_jwk_from_public_key():
    for algo in [
        AsymmetricAlgorithm.RS256,
        AsymmetricAlgorithm.RS384,
        AsymmetricAlgorithm.RS512,
    ]:
        public_key, _private_key = algo.generate_keypair()
        jwk = algo.to_jwk(public_key)

        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == algo.name
        assert jwk["use"] == "sig"
        assert "n" in jwk
        assert "e" in jwk
        assert isinstance(jwk["n"], str)
        assert isinstance(jwk["e"], str)


def test_rsa_pss_jwk_from_public_key():
    for algo in [
        AsymmetricAlgorithm.PS256,
        AsymmetricAlgorithm.PS384,
        AsymmetricAlgorithm.PS512,
    ]:
        public_key, _private_key = algo.generate_keypair()
        jwk = algo.to_jwk(public_key)

        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == algo.name
        assert jwk["use"] == "sig"
        assert "n" in jwk
        assert "e" in jwk


def test_ecdsa_jwk_from_public_key():
    expected_curves = {
        AsymmetricAlgorithm.ES256: "P-256",
        AsymmetricAlgorithm.ES384: "P-384",
        AsymmetricAlgorithm.ES512: "P-521",
    }
    for algo, expected_crv in expected_curves.items():
        public_key, _private_key = algo.generate_keypair()
        jwk = algo.to_jwk(public_key)

        assert "crv" in jwk
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == expected_crv
        assert jwk["alg"] == algo.name
        assert jwk["use"] == "sig"
        assert "x" in jwk
        assert "y" in jwk
        assert isinstance(jwk["x"], str)
        assert isinstance(jwk["y"], str)


def test_eddsa_jwk_from_public_key():
    algo = AsymmetricAlgorithm.EdDSA
    public_key, _private_key = algo.generate_keypair()
    jwk = algo.to_jwk(public_key)

    assert "crv" in jwk
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"
    assert jwk["use"] == "sig"
    assert "x" in jwk
    assert isinstance(jwk["x"], str)


def test_jwk_from_private_key():
    """Passing a private key should extract the public key and produce the same JWK."""
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()
        jwk_from_public = algo.to_jwk(public_key)
        jwk_from_private = algo.to_jwk(private_key)

        assert jwk_from_public == jwk_from_private


def test_jwk_from_pem_bytes():
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwk_from_obj = algo.to_jwk(public_key)
        jwk_from_bytes = algo.to_jwk(public_bytes)

        assert jwk_from_obj == jwk_from_bytes


def test_jwk_from_pem_str():
    for algo in AsymmetricAlgorithm:
        public_key, _private_key = algo.generate_keypair()

        public_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        jwk_from_obj = algo.to_jwk(public_key)
        jwk_from_str = algo.to_jwk(public_str)

        assert jwk_from_obj == jwk_from_str


def test_jwk_from_path(tmp_path: Path):
    for algo in AsymmetricAlgorithm:
        public_key, _private_key = algo.generate_keypair()

        public_path = tmp_path / f"public_{algo.name}.pem"
        public_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        jwk_from_obj = algo.to_jwk(public_key)
        jwk_from_path = algo.to_jwk(public_path)

        assert jwk_from_obj == jwk_from_path


def test_jwk_from_private_key_pem_bytes():
    """Loading a private key from PEM bytes should extract the public key."""
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        jwk_from_public = algo.to_jwk(public_key)
        jwk_from_private_bytes = algo.to_jwk(private_bytes)

        assert jwk_from_public == jwk_from_private_bytes


def test_jwk_from_private_key_path(tmp_path: Path):
    """Loading a private key from a file should extract the public key."""
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_path = tmp_path / f"private_{algo.name}.pem"
        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        jwk_from_public = algo.to_jwk(public_key)
        jwk_from_private_path = algo.to_jwk(private_path)

        assert jwk_from_public == jwk_from_private_path


def test_jwk_algorithm_key_mismatch():
    """Using an EC key with an RSA algorithm should raise ValueError."""
    ec_public, _ec_private = AsymmetricAlgorithm.ES256.generate_keypair()

    with pytest.raises(ValueError):
        AsymmetricAlgorithm.RS256.to_jwk(ec_public)


def test_jwk_deterministic():
    """Calling to_jwk twice on the same key should produce identical results."""
    for algo in AsymmetricAlgorithm:
        public_key, _private_key = algo.generate_keypair()
        jwk1 = algo.to_jwk(public_key)
        jwk2 = algo.to_jwk(public_key)

        assert jwk1 == jwk2


def test_jwk_no_padding_chars():
    """Base64url values in JWK must not contain '=' padding."""
    for algo in AsymmetricAlgorithm:
        public_key, _private_key = algo.generate_keypair()
        jwk = algo.to_jwk(public_key)

        for value in jwk.values():
            if isinstance(value, str) and value not in (
                jwk["kty"],
                jwk["alg"],
                jwk["use"],
                jwk.get("crv", ""),
            ):
                assert "=" not in value
                assert "+" not in value
                assert "/" not in value


def test_include_private_false_by_default():
    """When include_private is not set, private key fields should be absent."""
    for algo in AsymmetricAlgorithm:
        _public_key, private_key = algo.generate_keypair()
        jwk = algo.to_jwk(private_key)

        assert "d" not in jwk
        assert "p" not in jwk
        assert "q" not in jwk
        assert "dp" not in jwk
        assert "dq" not in jwk
        assert "qi" not in jwk


def test_include_private_with_public_key_has_no_private_fields():
    """When include_private=True but a public key is given, no private fields appear."""
    for algo in AsymmetricAlgorithm:
        public_key, _private_key = algo.generate_keypair()
        jwk = algo.to_jwk(public_key, include_private=True)

        assert "d" not in jwk
        assert "p" not in jwk
        assert "q" not in jwk
        assert "dp" not in jwk
        assert "dq" not in jwk
        assert "qi" not in jwk


def test_rsa_include_private():
    """RSA JWK with include_private should contain d, p, q, dp, dq, qi."""
    for algo in [
        AsymmetricAlgorithm.RS256,
        AsymmetricAlgorithm.RS384,
        AsymmetricAlgorithm.RS512,
        AsymmetricAlgorithm.PS256,
        AsymmetricAlgorithm.PS384,
        AsymmetricAlgorithm.PS512,
    ]:
        public_key, private_key = algo.generate_keypair()
        jwk = algo.to_jwk(private_key, include_private=True)

        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == algo.name
        assert "n" in jwk
        assert "e" in jwk
        assert "d" in jwk
        assert "p" in jwk
        assert "q" in jwk
        assert "dp" in jwk
        assert "dq" in jwk
        assert "qi" in jwk

        # Public-only JWK should be a subset
        jwk_public = algo.to_jwk(public_key)
        for k in ("kty", "n", "e", "alg", "use"):
            assert jwk[k] == jwk_public.get(k)


def test_ecdsa_include_private():
    """ECDSA JWK with include_private should contain d."""
    for algo in [
        AsymmetricAlgorithm.ES256,
        AsymmetricAlgorithm.ES384,
        AsymmetricAlgorithm.ES512,
    ]:
        public_key, private_key = algo.generate_keypair()
        jwk = algo.to_jwk(private_key, include_private=True)

        assert jwk["kty"] == "EC"
        assert "crv" in jwk
        assert "x" in jwk
        assert "y" in jwk
        assert "d" in jwk

        # Public-only fields should match
        jwk_public = algo.to_jwk(public_key)
        for k in ("kty", "crv", "x", "y", "alg", "use"):
            assert jwk[k] == jwk_public.get(k)


def test_eddsa_include_private():
    """EdDSA JWK with include_private should contain d."""
    algo = AsymmetricAlgorithm.EdDSA
    public_key, private_key = algo.generate_keypair()
    jwk = algo.to_jwk(private_key, include_private=True)

    assert jwk["kty"] == "OKP"
    assert "crv" in jwk
    assert jwk["crv"] == "Ed25519"
    assert "x" in jwk
    assert "d" in jwk

    # Public-only fields should match
    jwk_public = algo.to_jwk(public_key)
    for k in ("kty", "crv", "x", "alg", "use"):
        assert jwk[k] == jwk_public.get(k)


def test_include_private_from_pem_bytes():
    """include_private should work when loading a private key from PEM bytes."""
    for algo in AsymmetricAlgorithm:
        _public_key, private_key = algo.generate_keypair()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        jwk = algo.to_jwk(private_bytes, include_private=True)
        jwk_from_obj = algo.to_jwk(private_key, include_private=True)

        assert jwk == jwk_from_obj
        assert "d" in jwk


def test_include_private_from_path(tmp_path: Path):
    """include_private should work when loading a private key from a file."""
    for algo in AsymmetricAlgorithm:
        _public_key, private_key = algo.generate_keypair()

        private_path = tmp_path / f"private_{algo.name}.pem"
        private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        jwk = algo.to_jwk(private_path, include_private=True)
        jwk_from_obj = algo.to_jwk(private_key, include_private=True)

        assert jwk == jwk_from_obj
        assert "d" in jwk
