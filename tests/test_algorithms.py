import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from jws_algorithms.algorithms import AsymmetricAlgorithm, SymmetricAlgorithm


def test_symmetric_sign_and_verify():
    payload = b"message"

    for algo in SymmetricAlgorithm:
        secret = algo.generate_secret()
        signature = algo.sign(secret, payload)
        assert algo.verify(secret, payload, signature)

        # Test with an invalid signature
        assert not algo.verify(secret, payload, b"invalid_signature")

        # Test with a modified payload
        assert not algo.verify(secret, b"modified_payload", signature)

        # Test with a different key
        assert not algo.verify(b"different_key", payload, signature)


def test_rsa_sign_and_verify():
    payload = b"rsa is awesome"

    for algo in [
        AsymmetricAlgorithm.RS256,
        AsymmetricAlgorithm.RS384,
        AsymmetricAlgorithm.RS512,
    ]:
        public_key, private_key = algo.generate_keypair()
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        signature = algo.sign(private_key, payload)
        assert algo.verify(public_key, payload, signature)

        # Test with an invalid signature
        assert not algo.verify(public_key, payload, b"invalid_signature")

        # Test with a modified payload
        assert not algo.verify(public_key, b"modified_payload", signature)


def test_ecdsa_sign_and_verify():
    payload = b"my secret ecdsa message"

    for algo in [
        AsymmetricAlgorithm.ES256,
        AsymmetricAlgorithm.ES384,
        AsymmetricAlgorithm.ES512,
    ]:
        public_key, private_key = algo.generate_keypair()
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        signature = algo.sign(private_key, payload)
        assert algo.verify(public_key, payload, signature)

        # Test with an invalid signature
        assert not algo.verify(public_key, payload, b"invalid_signature")

        # Test with a modified payload
        assert not algo.verify(public_key, b"modified_payload", signature)


def test_psign_and_verify():
    payload = b"my secret p message"

    for algo in [
        AsymmetricAlgorithm.PS256,
        AsymmetricAlgorithm.PS384,
        AsymmetricAlgorithm.PS512,
    ]:
        public_key, private_key = algo.generate_keypair()
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        signature = algo.sign(private_key, payload)
        assert algo.verify(public_key, payload, signature)

        # Test with an invalid signature
        assert not algo.verify(public_key, payload, b"invalid_signature")

        # Test with a modified payload
        assert not algo.verify(public_key, b"modified_payload", signature)


def test_ed25519_sign_and_verify():
    payload = b"my secret ed25519 message"

    algo = AsymmetricAlgorithm.EdDSA
    public_key, private_key = algo.generate_keypair()
    assert isinstance(private_key, ed25519.Ed25519PrivateKey)
    assert isinstance(public_key, ed25519.Ed25519PublicKey)
    signature = algo.sign(private_key, payload)
    assert algo.verify(public_key, payload, signature)

    # Test with an invalid signature
    assert not algo.verify(public_key, payload, b"invalid_signature")

    # Test with a modified payload
    assert not algo.verify(public_key, b"modified_payload", signature)


# Symmetric algorithm tests for all combinations
def test_symmetric_bytes_payload_bytes_secret():
    payload = b"test payload"
    for algo in SymmetricAlgorithm:
        secret = algo.generate_secret()
        signature = algo.sign(secret, payload)
        assert algo.verify(secret, payload, signature)


def test_symmetric_bytes_payload_str_secret():
    payload = b"test payload"
    for algo in SymmetricAlgorithm:
        secret = algo.generate_secret()
        signature = algo.sign(secret, payload)
        assert algo.verify(secret, payload, signature)


def test_symmetric_bytes_payload_path_secret(tmp_path: Path):
    payload = b"test payload"
    for algo in SymmetricAlgorithm:
        secret_bytes = algo.generate_secret()
        secret_path = tmp_path / f"secret_{algo.name}.key"

        secret_path.write_bytes(secret_bytes.secret_bytes)
        signature = algo.sign(secret_path, payload)
        assert algo.verify(secret_path, payload, signature)


def test_symmetric_str_payload_bytes_secret():
    payload = "test payload"
    for algo in SymmetricAlgorithm:
        secret = algo.generate_secret()
        signature = algo.sign(secret, payload)
        assert algo.verify(secret, payload, signature)


def test_symmetric_str_payload_str_secret():
    payload = "test payload"
    for algo in SymmetricAlgorithm:
        secret = algo.generate_secret()
        signature = algo.sign(secret, payload)
        assert algo.verify(secret, payload, signature)


def test_symmetric_str_payload_path_secret(tmp_path: Path):
    payload = "test payload"
    for algo in SymmetricAlgorithm:
        secret_bytes = algo.generate_secret()
        secret_path = tmp_path / f"secret_{algo.name}.key"

        secret_path.write_bytes(secret_bytes.secret_bytes)
        signature = algo.sign(secret_path, payload)
        assert algo.verify(secret_path, payload, signature)


# Asymmetric algorithm tests for all combinations
def test_asymmetric_bytes_payload_bytes_keys():
    payload = b"test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        # Serialize keys to bytes
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signature = algo.sign(private_bytes, payload)
        assert algo.verify(public_bytes, payload, signature)


def test_asymmetric_bytes_payload_str_keys():
    payload = b"test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        # Serialize keys to strings
        private_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        signature = algo.sign(private_str, payload)
        assert algo.verify(public_str, payload, signature)


def test_asymmetric_bytes_payload_path_keys(tmp_path: Path):
    payload = b"test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        # Write keys to files
        private_path = tmp_path / f"private_{algo.name}.pem"
        public_path = tmp_path / f"public_{algo.name}.pem"

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)

        signature = algo.sign(private_path, payload)
        assert algo.verify(public_path, payload, signature)


def test_asymmetric_str_payload_bytes_keys():
    payload = "test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        # Serialize keys to bytes
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signature = algo.sign(private_bytes, payload=payload)
        assert algo.verify(public_bytes, payload=payload, signature=signature)


def test_asymmetric_str_payload_str_keys():
    payload = "test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        # Serialize keys to strings
        private_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        signature = algo.sign(private_str, payload=payload)
        assert algo.verify(public_str, payload=payload, signature=signature)


def test_asymmetric_str_payload_path_keys(tmp_path: Path):
    payload = "test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        # Write keys to files
        private_path = tmp_path / f"private_{algo.name}.pem"
        public_path = tmp_path / f"public_{algo.name}.pem"

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_path.write_bytes(private_bytes)
        public_path.write_bytes(public_bytes)

        signature = algo.sign(private_path, payload)
        assert algo.verify(public_path, payload, signature)


# Additional combination tests for asymmetric - mixed key types
def test_asymmetric_bytes_payload_bytes_private_str_public():
    payload = b"test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        signature = algo.sign(private_bytes, payload)
        assert algo.verify(public_str, payload, signature)


def test_asymmetric_bytes_payload_str_private_path_public(tmp_path: Path):
    payload = b"test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_path = tmp_path / f"public_{algo.name}.pem"
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_path.write_bytes(public_bytes)

        signature = algo.sign(private_str, payload)
        assert algo.verify(public_path, payload, signature)


def test_asymmetric_bytes_payload_path_private_bytes_public(tmp_path: Path):
    payload = b"test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_path = tmp_path / f"private_{algo.name}.pem"
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_path.write_bytes(private_bytes)

        signature = algo.sign(private_path, payload)
        assert algo.verify(public_bytes, payload, signature)


def test_asymmetric_str_payload_bytes_private_path_public(tmp_path: Path):
    payload = "test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_path = tmp_path / f"public_{algo.name}.pem"
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_path.write_bytes(public_bytes)

        signature = algo.sign(private_bytes, payload)
        assert algo.verify(public_path, payload, signature)


def test_asymmetric_str_payload_path_private_str_public(tmp_path: Path):
    payload = "test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_path = tmp_path / f"private_{algo.name}.pem"
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        private_path.write_bytes(private_bytes)

        signature = algo.sign(private_path, payload)
        assert algo.verify(public_str, payload, signature)


def test_asymmetric_str_payload_str_private_bytes_public():
    payload = "test payload"
    for algo in AsymmetricAlgorithm:
        public_key, private_key = algo.generate_keypair()

        private_str = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        signature = algo.sign(private_str, payload)
        assert algo.verify(public_bytes, payload, signature)


def test_signing_and_verifying_encrypted_private_keys(tmp_path: Path):
    try:
        import bcrypt  # noqa: F401, PLC0415
    except ImportError:
        pytest.skip("bcrypt not installed, skipping encrypted key tests.")
    payload = b"test payload with encrypted RSA key"
    password = b"test_password_123"

    for algo in AsymmetricAlgorithm:
        [public_key, private_key] = algo.generate_keypair()

        encrypted_private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=(
                serialization.PrivateFormat.OpenSSH
                if algo is AsymmetricAlgorithm.EdDSA
                else serialization.PrivateFormat.TraditionalOpenSSL
            ),
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )

        with pytest.raises(ValueError):
            algo.sign(encrypted_private_bytes, payload, password=b"wrong_password")

        signature = algo.sign(
            private_key=encrypted_private_bytes, payload=payload, password=password
        )

        assert algo.verify(public_key=public_key, payload=payload, signature=signature)

        # Write the encrypted private key to a file
        encrypted_private_key_path = tmp_path / f"private_{algo.name}.pem"
        encrypted_private_key_path.write_bytes(encrypted_private_bytes)

        with pytest.raises(ValueError):
            algo.sign(
                encrypted_private_key_path,
                payload=payload,
                password=b"wrong_password",
            )

        signature_from_file = algo.sign(
            encrypted_private_key_path,
            payload=payload,
            password=password,
        )

        assert algo.verify(
            public_key,
            payload=payload,
            signature=signature_from_file,
        )


def test_signing_and_verifying_encrypted_ssh_key(tmp_path: Path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen not found, skipping test.")
    try:
        import bcrypt  # noqa: F401, PLC0415
    except ImportError:
        pytest.skip("bcrypt not installed, skipping encrypted key tests.")

    payload = b"test payload with encrypted ssh-keygen key"
    password = "test_password_ssh"
    keyfile = tmp_path / "id_ed25519"
    pubfile = tmp_path / "id_ed25519.pub"

    # Generate encrypted Ed25519 private key using ssh-keygen
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-N",
            password,
            "-f",
            str(keyfile),
            "-q",
        ],
        check=True,
    )

    algo = AsymmetricAlgorithm.EdDSA

    with pytest.raises(ValueError):
        algo.sign(
            private_key=keyfile,
            payload=payload,
            password="wrong_encryption_password",
        )

    signature = algo.sign(private_key=keyfile, payload=payload, password=password)

    assert algo.verify(public_key=pubfile, payload=payload, signature=signature)


def test_ssh_keygen_rsa(tmp_path: Path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen not found, skipping test.")

    payload = b"test payload with encrypted ssh-keygen RSA key"
    keyfile = tmp_path / "id_rsa"
    pubfile = tmp_path / "id_rsa.pub"

    # Generate encrypted RSA private key using ssh-keygen
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            "",
            "-f",
            str(keyfile),
            "-q",
        ],
        check=True,
    )

    for algo in [
        AsymmetricAlgorithm.RS256,
        AsymmetricAlgorithm.RS384,
        AsymmetricAlgorithm.RS512,
        AsymmetricAlgorithm.PS256,
        AsymmetricAlgorithm.PS384,
        AsymmetricAlgorithm.PS512,
    ]:
        signature = algo.sign(private_key=keyfile, payload=payload)

        assert algo.verify(public_key=pubfile, payload=payload, signature=signature)


def test_ssh_keygen_rsa_with_password(tmp_path: Path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen not found, skipping test.")
    try:
        import bcrypt  # noqa: F401, PLC0415
    except ImportError:
        pytest.skip("bcrypt not installed, skipping encrypted key tests.")

    payload = b"test payload with encrypted ssh-keygen RSA key"
    password = "test_password_ssh_rsa"
    keyfile = tmp_path / "id_rsa"
    pubfile = tmp_path / "id_rsa.pub"

    # Generate encrypted RSA private key using ssh-keygen
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "rsa",
            "-b",
            "2048",
            "-N",
            password,
            "-f",
            str(keyfile),
            "-q",
        ],
        check=True,
    )

    for algo in [
        AsymmetricAlgorithm.RS256,
        AsymmetricAlgorithm.RS384,
        AsymmetricAlgorithm.RS512,
        AsymmetricAlgorithm.PS256,
        AsymmetricAlgorithm.PS384,
        AsymmetricAlgorithm.PS512,
    ]:
        with pytest.raises(ValueError):
            algo.sign(
                payload=payload,
                private_key=keyfile,
                password="wrong_encryption_password",
            )

        signature = algo.sign(private_key=keyfile, payload=payload, password=password)

        assert algo.verify(public_key=pubfile, payload=payload, signature=signature)


def test_ssh_keygen_ecdsa(tmp_path: Path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen not found, skipping test.")

    payload = b"test payload with encrypted ssh-keygen ECDSA key"
    keyfile = tmp_path / "id_ecdsa"
    pubfile = tmp_path / "id_ecdsa.pub"

    # Generate encrypted ECDSA private key using ssh-keygen
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ecdsa",
            "-b",
            "256",
            "-N",
            "",
            "-f",
            str(keyfile),
            "-q",
        ],
        check=True,
    )

    for algo in [
        AsymmetricAlgorithm.ES256,
        AsymmetricAlgorithm.ES384,
        AsymmetricAlgorithm.ES512,
    ]:
        signature = algo.sign(private_key=keyfile, payload=payload)

        assert algo.verify(public_key=pubfile, payload=payload, signature=signature)


def test_ssh_keygen_encrypted_ecdsa(tmp_path: Path):
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen not found, skipping test.")
    try:
        import bcrypt  # noqa: F401, PLC0415
    except ImportError:
        pytest.skip("bcrypt not installed, skipping encrypted key tests.")

    payload = b"test payload with encrypted ssh-keygen ECDSA key"
    password = "test_password_ssh_ecdsa"
    keyfile = tmp_path / "id_ecdsa"
    pubfile = tmp_path / "id_ecdsa.pub"

    # Generate encrypted ECDSA private key using ssh-keygen
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ecdsa",
            "-b",
            "256",
            "-N",
            password,
            "-f",
            str(keyfile),
            "-q",
        ],
        check=True,
    )

    for algo in [
        AsymmetricAlgorithm.ES256,
        AsymmetricAlgorithm.ES384,
        AsymmetricAlgorithm.ES512,
    ]:
        with pytest.raises(ValueError):
            algo.sign(
                private_key=keyfile,
                payload=payload,
                password="wrong_encryption_password",
            )

        signature = algo.sign(private_key=keyfile, payload=payload, password=password)

        assert algo.verify(public_key=pubfile, payload=payload, signature=signature)


def test_asymmetric_algorithm_and_key_mismatch():
    payload = b"test payload"
    algo = AsymmetricAlgorithm.RS256
    public_key, private_key = AsymmetricAlgorithm.ES256.generate_keypair()

    with pytest.raises(ValueError):
        algo.sign(private_key=private_key, payload=payload)

    signature = algo.sign(
        private_key=AsymmetricAlgorithm.RS256.generate_keypair()[1], payload=payload
    )

    with pytest.raises(ValueError):
        algo.verify(public_key=public_key, payload=payload, signature=signature)
