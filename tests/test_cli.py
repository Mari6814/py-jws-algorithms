"""Tests for the CLI module."""

import base64
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from jws_algorithms.cli import generate_keys, sign, verify


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for test files."""
    return tmp_path


class TestGenerateKeys:
    """Tests for the generate_keys function."""

    def test_generate_symmetric_secret_to_file(self, temp_dir):
        """Test generating a symmetric secret to a file."""
        secret_file = temp_dir / "secret.key"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        assert secret_file.exists()
        secret_content = secret_file.read_bytes()
        assert len(secret_content) == 32  # 256 bits = 32 bytes for HS256

    def test_generate_symmetric_secret_custom_bytes(self, temp_dir):
        """Test generating a symmetric secret with custom byte length."""
        secret_file = temp_dir / "secret.key"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
                "--secret-bytes",
                "16",
            ],
        ):
            generate_keys()

        assert secret_file.exists()
        secret_content = secret_file.read_bytes()
        assert len(secret_content) == 16

    def test_generate_symmetric_secret_base64(self, temp_dir):
        """Test generating a symmetric secret encoded in base64."""
        secret_file = temp_dir / "secret.key"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
                "--base64",
            ],
        ):
            generate_keys()

        assert secret_file.exists()
        secret_content = secret_file.read_bytes()
        # Should be base64 encoded, so try to decode it
        decoded = base64.b64decode(secret_content)
        assert len(decoded) == 32  # Original should be 32 bytes

    def test_generate_asymmetric_keypair(self, temp_dir):
        """Test generating an asymmetric key pair."""
        private_file = temp_dir / "private.pem"
        public_file = temp_dir / "public.pem"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "RS256",
                "--output-private",
                str(private_file),
                "--output-public",
                str(public_file),
            ],
        ):
            generate_keys()

        assert private_file.exists()
        assert public_file.exists()

        # Verify the keys are valid PEM format
        private_content = private_file.read_text()
        public_content = public_file.read_text()

        assert "-----BEGIN PRIVATE KEY-----" in private_content
        assert "-----BEGIN PUBLIC KEY-----" in public_content

    def test_generate_asymmetric_keypair_der_format(self, temp_dir):
        """Test generating an asymmetric key pair in DER format."""
        private_file = temp_dir / "private.der"
        public_file = temp_dir / "public.der"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "RS256",
                "--format",
                "DER",
                "--output-private",
                str(private_file),
                "--output-public",
                str(public_file),
            ],
        ):
            generate_keys()

        assert private_file.exists()
        assert public_file.exists()

        # DER files are binary
        private_content = private_file.read_bytes()
        public_content = public_file.read_bytes()

        assert len(private_content) > 0
        assert len(public_content) > 0

    def test_generate_keys_missing_algorithm(self):
        """Test that missing algorithm raises SystemExit."""
        with patch("sys.argv", ["jws-gen-keys"]):
            with pytest.raises(SystemExit):
                generate_keys()

    def test_generate_symmetric_with_asymmetric_options(self):
        """Test that using asymmetric options with symmetric algorithm fails."""
        with patch(
            "sys.argv",
            ["jws-gen-keys", "--algorithm", "HS256", "--output-private", "private.pem"],
        ):
            with pytest.raises(SystemExit):
                generate_keys()

    def test_generate_asymmetric_with_symmetric_options(self):
        """Test that using symmetric options with asymmetric algorithm fails."""
        with patch(
            "sys.argv",
            ["jws-gen-keys", "--algorithm", "RS256", "--output-secret", "secret.key"],
        ):
            with pytest.raises(SystemExit):
                generate_keys()

    def test_generate_asymmetric_without_output(self):
        """Test that asymmetric algorithms require at least one output file."""
        with patch("sys.argv", ["jws-gen-keys", "--algorithm", "RS256"]):
            with pytest.raises(SystemExit):
                generate_keys()

    def test_file_permissions_symmetric_secret(self, temp_dir):
        """Test that symmetric secrets are created with secure permissions (600)."""
        import os
        import stat

        secret_file = temp_dir / "secret.key"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        assert secret_file.exists()
        # Check that file has 600 permissions (read/write for owner only)
        file_mode = stat.filemode(os.stat(secret_file).st_mode)
        assert file_mode == "-rw-------"  # 600 permissions

    def test_file_permissions_asymmetric_keys(self, temp_dir):
        """Test that private keys get 600 permissions and public keys get 644 permissions."""
        import os
        import stat

        private_file = temp_dir / "private.pem"
        public_file = temp_dir / "public.pem"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "RS256",
                "--output-private",
                str(private_file),
                "--output-public",
                str(public_file),
            ],
        ):
            generate_keys()

        assert private_file.exists()
        assert public_file.exists()

        # Check private key has 600 permissions (read/write for owner only)
        private_mode = stat.filemode(os.stat(private_file).st_mode)
        assert private_mode == "-rw-------"  # 600 permissions

        # Check public key has 644 permissions (read for all, write for owner)
        public_mode = stat.filemode(os.stat(public_file).st_mode)
        assert public_mode == "-rw-r--r--"  # 644 permissions


class TestSign:
    """Tests for the sign function."""

    @pytest.fixture
    def symmetric_secret(self, temp_dir):
        """Create a symmetric secret file for testing."""
        secret_file = temp_dir / "secret.key"
        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()
        return secret_file

    @pytest.fixture
    def asymmetric_keys(self, temp_dir):
        """Create asymmetric key pair for testing."""
        private_file = temp_dir / "private.pem"
        public_file = temp_dir / "public.pem"
        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "RS256",
                "--output-private",
                str(private_file),
                "--output-public",
                str(public_file),
            ],
        ):
            generate_keys()
        return private_file, public_file

    def test_sign_with_symmetric_secret(self, temp_dir, symmetric_secret):
        """Test signing with a symmetric secret."""
        message_file = temp_dir / "message.txt"
        signature_file = temp_dir / "signature.bin"
        message_file.write_text("Hello World")

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(symmetric_secret),
                "--input",
                str(message_file),
                "--output",
                str(signature_file),
            ],
        ):
            sign()

        assert signature_file.exists()
        signature = signature_file.read_bytes()
        assert len(signature) > 0

    def test_sign_with_text_input(self, temp_dir, symmetric_secret):
        """Test signing with direct text input."""
        signature_file = temp_dir / "signature.bin"

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(symmetric_secret),
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
            ],
        ):
            sign()

        assert signature_file.exists()
        signature = signature_file.read_bytes()
        assert len(signature) > 0

    def test_sign_with_base64_output(self, temp_dir, symmetric_secret):
        """Test signing with base64 encoded output."""
        signature_file = temp_dir / "signature.txt"

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(symmetric_secret),
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
                "--base64",
            ],
        ):
            sign()

        assert signature_file.exists()
        signature_content = signature_file.read_bytes()

        # Should be base64 encoded
        decoded = base64.b64decode(signature_content)
        assert len(decoded) > 0

    def test_sign_with_urlsafe_base64_output(self, temp_dir, symmetric_secret):
        """Test signing with URL-safe base64 encoded output."""
        signature_file = temp_dir / "signature.txt"

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(symmetric_secret),
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
                "--url-safe",
            ],
        ):
            sign()

        assert signature_file.exists()
        signature_content = signature_file.read_bytes()

        # Should be URL-safe base64 encoded
        decoded = base64.urlsafe_b64decode(signature_content)
        assert len(decoded) > 0

    def test_sign_with_asymmetric_key(self, temp_dir, asymmetric_keys):
        """Test signing with an asymmetric private key."""
        private_file, _ = asymmetric_keys
        signature_file = temp_dir / "signature.bin"

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "RS256",
                "--private-key",
                str(private_file),
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
            ],
        ):
            sign()

        assert signature_file.exists()
        signature = signature_file.read_bytes()
        assert len(signature) > 0

    def test_sign_with_stdin(self, temp_dir, symmetric_secret, monkeypatch):
        """Test signing with stdin input."""
        import io

        signature_file = temp_dir / "signature.bin"

        # Create a mock stdin with buffer attribute
        class MockStdin:
            def __init__(self):
                self.buffer = io.BytesIO(b"Hello from stdin")

        monkeypatch.setattr("sys.stdin", MockStdin())

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(symmetric_secret),
                "--output",
                str(signature_file),
            ],
        ):
            sign()

        assert signature_file.exists()
        signature = signature_file.read_bytes()
        assert len(signature) > 0

    def test_sign_missing_algorithm(self):
        """Test that missing algorithm raises SystemExit."""
        with patch("sys.argv", ["jws-sign"]):
            with pytest.raises(SystemExit):
                sign()

    def test_sign_symmetric_with_private_key(self, temp_dir, asymmetric_keys):
        """Test that symmetric algorithms can't use private keys."""
        private_file, _ = asymmetric_keys

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--private-key",
                str(private_file),
                "--text",
                "Hello",
            ],
        ):
            with pytest.raises(SystemExit):
                sign()

    def test_sign_asymmetric_with_secret(self, temp_dir, symmetric_secret):
        """Test that asymmetric algorithms can't use secrets."""
        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "RS256",
                "--secret",
                str(symmetric_secret),
                "--text",
                "Hello",
            ],
        ):
            with pytest.raises(SystemExit):
                sign()


class TestVerify:
    """Tests for the verify function."""

    @pytest.fixture
    def signed_data(self, temp_dir):
        """Create signed data for testing verification."""
        # Generate secret
        secret_file = temp_dir / "secret.key"
        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        # Create message
        message_file = temp_dir / "message.txt"
        message_file.write_text("Hello World")

        # Sign message
        signature_file = temp_dir / "signature.bin"
        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--input",
                str(message_file),
                "--output",
                str(signature_file),
            ],
        ):
            sign()

        return secret_file, message_file, signature_file

    @pytest.fixture
    def signed_asymmetric_data(self, temp_dir):
        """Create asymmetrically signed data for testing verification."""
        # Generate keys
        private_file = temp_dir / "private.pem"
        public_file = temp_dir / "public.pem"
        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "RS256",
                "--output-private",
                str(private_file),
                "--output-public",
                str(public_file),
            ],
        ):
            generate_keys()

        # Create message
        message_file = temp_dir / "message.txt"
        message_file.write_text("Hello World")

        # Sign message
        signature_file = temp_dir / "signature.bin"
        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "RS256",
                "--private-key",
                str(private_file),
                "--input",
                str(message_file),
                "--output",
                str(signature_file),
            ],
        ):
            sign()

        return private_file, public_file, message_file, signature_file

    def test_verify_valid_symmetric_signature(self, signed_data):
        """Test verifying a valid symmetric signature."""
        secret_file, message_file, signature_file = signed_data

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--input",
                str(message_file),
                "--signature",
                str(signature_file),
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 0  # Success exit code

    def test_verify_invalid_symmetric_signature(self, temp_dir, signed_data):
        """Test verifying an invalid symmetric signature."""
        secret_file, message_file, _ = signed_data

        # Create a fake signature
        fake_signature_file = temp_dir / "fake_signature.bin"
        fake_signature_file.write_bytes(b"invalid_signature")

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--input",
                str(message_file),
                "--signature",
                str(fake_signature_file),
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 1  # Failure exit code

    def test_verify_valid_asymmetric_signature(self, signed_asymmetric_data):
        """Test verifying a valid asymmetric signature."""
        _, public_file, message_file, signature_file = signed_asymmetric_data

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "RS256",
                "--public-key",
                str(public_file),
                "--input",
                str(message_file),
                "--signature",
                str(signature_file),
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 0  # Success exit code

    def test_verify_with_text_input(self, signed_data):
        """Test verifying with direct text input."""
        secret_file, _, signature_file = signed_data

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello World",
                "--signature",
                str(signature_file),
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 0  # Success exit code

    def test_verify_with_base64_signature(self, temp_dir):
        """Test verifying with base64-encoded signature."""
        # Generate secret and sign with base64
        secret_file = temp_dir / "secret.key"
        signature_file = temp_dir / "signature.txt"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
                "--base64",
            ],
        ):
            sign()

        # Get the base64 signature
        base64_signature = signature_file.read_text().strip()

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello World",
                "--signature-base64",
                base64_signature,
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 0  # Success exit code

    def test_verify_with_urlsafe_base64_signature(self, temp_dir):
        """Test verifying with URL-safe base64-encoded signature."""
        # Generate secret and sign with URL-safe base64
        secret_file = temp_dir / "secret.key"
        signature_file = temp_dir / "signature.txt"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                # TODO: --text should be --input or --payload
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
                "--url-safe",
            ],
        ):
            sign()

        # Get the URL-safe base64 signature
        urlsafe_signature = signature_file.read_text().strip()

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                # TODO: Delete this parameter ??? --text makes no sense here. It should be --input or --payload
                "--text",
                "Hello World",
                "--signature-urlsafe",
                urlsafe_signature,
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 0  # Success exit code

    def test_verify_with_stdin(self, signed_data, monkeypatch):
        """Test verifying with stdin input."""
        import io

        secret_file, _, signature_file = signed_data

        # Create a mock stdin with buffer attribute
        class MockStdin:
            def __init__(self):
                self.buffer = io.BytesIO(b"Hello World")

        monkeypatch.setattr("sys.stdin", MockStdin())

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--signature",
                str(signature_file),
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                verify()
            assert exc_info.value.code == 0  # Success exit code

    def test_verify_missing_algorithm(self):
        """Test that missing algorithm raises SystemExit."""
        with patch("sys.argv", ["jws-verify"]):
            with pytest.raises(SystemExit):
                verify()

    def test_verify_symmetric_with_public_key(self, temp_dir, signed_asymmetric_data):
        """Test that symmetric algorithms can't use public keys."""
        _, public_file, _, _ = signed_asymmetric_data

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--public-key",
                str(public_file),
                "--text",
                "Hello",
                "--signature-base64",
                "dGVzdA==",
            ],
        ):
            with pytest.raises(SystemExit):
                verify()

    def test_verify_asymmetric_with_secret(self, temp_dir, signed_data):
        """Test that asymmetric algorithms can't use secrets."""
        secret_file, _, _ = signed_data

        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "RS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello",
                "--signature-base64",
                "dGVzdA==",
            ],
        ):
            with pytest.raises(SystemExit):
                verify()


class TestCLIIntegration:
    """Integration tests for the CLI using subprocess."""

    def test_cli_help_commands(self):
        """Test that CLI help commands work properly."""
        # Test the module help
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from jws_algorithms.cli import generate_keys; import sys; sys.argv = ['test', '--help']; generate_keys()",
            ],
            capture_output=True,
            text=True,
        )
        assert "Generate keys or secrets for JWS algorithms" in result.stdout

    def test_algorithm_choices(self):
        """Test that all expected algorithms are available as choices."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from jws_algorithms.cli import generate_keys; import sys; sys.argv = ['test', '--help']; generate_keys()",
            ],
            capture_output=True,
            text=True,
        )

        # Check that all expected algorithms are in the help text
        expected_algorithms = [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
        ]

        for alg in expected_algorithms:
            assert alg in result.stdout


class TestErrorHandling:
    """Tests for error handling in CLI functions."""

    def test_invalid_algorithm(self):
        """Test handling of invalid algorithm names."""
        with patch(
            "sys.argv",
            ["jws-gen-keys", "--algorithm", "INVALID", "--output-secret", "secret.key"],
        ):
            with pytest.raises(SystemExit):
                generate_keys()

    def test_missing_required_args(self):
        """Test handling of missing required arguments."""
        # Missing algorithm
        with patch("sys.argv", ["jws-gen-keys"]):
            with pytest.raises(SystemExit):
                generate_keys()

        # Missing key/secret for signing
        with patch("sys.argv", ["jws-sign", "--algorithm", "HS256", "--text", "hello"]):
            with pytest.raises(SystemExit):
                sign()

        # Missing signature for verification
        with patch(
            "sys.argv",
            [
                "jws-verify",
                "--algorithm",
                "HS256",
                "--secret",
                "secret.key",
                "--text",
                "hello",
            ],
        ):
            with pytest.raises(SystemExit):
                verify()

    def test_file_not_found_handling(self, temp_dir):
        """Test handling of non-existent files."""
        nonexistent_file = temp_dir / "nonexistent.key"

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(nonexistent_file),
                "--text",
                "hello",
            ],
        ):
            with pytest.raises(SystemExit):
                sign()


class TestUrlSafeBase64:
    """Tests for URL-safe base64 functionality."""

    def test_urlsafe_implies_base64_sign(self, temp_dir):
        """Test that --url-safe implies --base64 for signing."""
        # Generate a secret first
        secret_file = temp_dir / "secret.key"
        signature_file = temp_dir / "signature.txt"

        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello World",
                "--output",
                str(signature_file),
                "--url-safe",
            ],
        ):
            sign()

        assert signature_file.exists()
        signature_content = signature_file.read_bytes()

        # Should be URL-safe base64 encoded
        decoded = base64.urlsafe_b64decode(signature_content)
        assert len(decoded) > 0

    def test_urlsafe_vs_regular_base64_different_output(self, temp_dir):
        """Test that URL-safe and regular base64 can produce different outputs."""
        secret_file = temp_dir / "secret.key"
        sig_regular = temp_dir / "sig_regular.txt"
        sig_urlsafe = temp_dir / "sig_urlsafe.txt"

        # Generate a secret
        with patch(
            "sys.argv",
            [
                "jws-gen-keys",
                "--algorithm",
                "HS256",
                "--output-secret",
                str(secret_file),
            ],
        ):
            generate_keys()

        # Sign with regular base64
        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello World",
                "--output",
                str(sig_regular),
                "--base64",
            ],
        ):
            sign()

        # Sign with URL-safe base64
        with patch(
            "sys.argv",
            [
                "jws-sign",
                "--algorithm",
                "HS256",
                "--secret",
                str(secret_file),
                "--text",
                "Hello World",
                "--output",
                str(sig_urlsafe),
                "--url-safe",
            ],
        ):
            sign()

        regular_content = sig_regular.read_bytes()
        urlsafe_content = sig_urlsafe.read_bytes()

        # Both should decode to the same binary data
        regular_decoded = base64.b64decode(regular_content)
        urlsafe_decoded = base64.urlsafe_b64decode(urlsafe_content)

        assert regular_decoded == urlsafe_decoded

        # But the encoded forms might be different if they contain +/= characters
        # (though they might be the same if no such characters are present)
