#!/usr/bin/env python3
"""Command-line interface for JWS algorithms.

This module provides easy-to-use CLI tools for:
- Generating keys/secrets for symmetric and asymmetric algorithms
- Signing payloads with various JWS algorithms
- Verifying signatures
"""

import argparse
import base64
import os
import sys
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives import serialization

from .algorithms import AsymmetricAlgorithm, SymmetricAlgorithm


def _encode_base64(data: bytes, url_safe: bool = False) -> bytes:
    """Encode data to base64, optionally using URL-safe encoding."""
    if url_safe:
        return base64.urlsafe_b64encode(data)
    else:
        return base64.b64encode(data)


def _decode_base64(data: str | bytes, url_safe: bool = False) -> bytes:
    """Decode base64 data, optionally using URL-safe decoding."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    if url_safe:
        return base64.urlsafe_b64decode(data)
    else:
        return base64.b64decode(data)


def _write_output(
    content: bytes | str,
    output_file: Path | None,
    secure: bool = False,
    public_key: bool = False,
) -> None:
    """Write content to file or stdout.

    Args:
        content: The content to write
        output_file: The file path to write to, or None for stdout
        secure: If True, set restrictive permissions (600) like ssh-keygen for private keys/secrets
        public_key: If True, set public key permissions (644) like ssh-keygen for public keys
    """
    if isinstance(content, str):
        content = content.encode("utf-8")

    if output_file:
        # Write the file with default permissions first
        output_file.write_bytes(content)

        # Set appropriate permissions (like ssh-keygen does)
        if secure:
            # Set permissions to 600 (read/write for owner only) for private keys/secrets
            os.chmod(output_file, 0o600)
        elif public_key:
            # Set permissions to 644 (read for all, write for owner) for public keys
            os.chmod(output_file, 0o644)

        print(f"Output written to: {output_file}")
    else:
        # Write to stdout
        sys.stdout.buffer.write(content)
        sys.stdout.buffer.write(b"\n")


def _read_input(input_file: Path | None, input_text: str | None) -> bytes:
    """Read input from file, argument, or stdin."""
    if input_file:
        return input_file.read_bytes()
    elif input_text:
        return input_text.encode("utf-8")
    else:
        # Read from stdin
        return sys.stdin.buffer.read()


def _error_exit(message: str) -> NoReturn:
    """Print error message and exit."""
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


def generate_keys() -> None:
    """Generate keys or secrets for JWS algorithms."""
    parser = argparse.ArgumentParser(
        description="Generate keys or secrets for JWS algorithms",
        epilog="""
Examples:
  # Generate HMAC secret for HS256
  jws-gen-keys --algorithm HS256 --output-secret secret.key
  
  # Generate RSA key pair for RS256
  jws-gen-keys --algorithm RS256 --output-private private.pem --output-public public.pem
  
  # Generate ECDSA key pair for ES256 in DER format
  jws-gen-keys --algorithm ES256 --format DER --output-private private.der --output-public public.der
  
  # Generate HMAC secret with URL-safe base64 encoding
  jws-gen-keys --algorithm HS256 --url-safe
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--algorithm",
        "-a",
        required=True,
        choices=[alg.name for alg in SymmetricAlgorithm]
        + [alg.name for alg in AsymmetricAlgorithm],
        help="Algorithm to generate keys for",
    )

    parser.add_argument(
        "--output-secret",
        "-s",
        type=Path,
        help="Output file for symmetric algorithm secret (will be created with 600 permissions)",
    )

    parser.add_argument(
        "--output-private",
        "-p",
        type=Path,
        help="Output file for asymmetric algorithm private key (will be created with 600 permissions)",
    )

    parser.add_argument(
        "--output-public",
        "-u",
        type=Path,
        help="Output file for asymmetric algorithm public key (will be created with 644 permissions)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["PEM", "DER"],
        default="PEM",
        help="Key format for asymmetric algorithms (default: PEM)",
    )

    parser.add_argument(
        "--secret-bytes",
        "-b",
        type=int,
        help="Number of bytes for symmetric algorithm secret (uses algorithm default if not specified)",
    )

    parser.add_argument(
        "--base64", action="store_true", help="Encode symmetric secrets in base64"
    )

    args = parser.parse_args()

    # Check if algorithm is symmetric or asymmetric
    sym_alg = None
    asym_alg = None

    try:
        sym_alg = SymmetricAlgorithm[args.algorithm]
        is_symmetric = True
    except KeyError:
        try:
            asym_alg = AsymmetricAlgorithm[args.algorithm]
            is_symmetric = False
        except KeyError:
            _error_exit(f"Unknown algorithm: {args.algorithm}")

    if is_symmetric:
        if args.output_private or args.output_public:
            _error_exit(
                "Symmetric algorithms don't use private/public keys. Use --output-secret instead."
            )

        assert sym_alg is not None  # Type checker hint
        secret = sym_alg.generate_secret(args.secret_bytes)
        secret_bytes = secret.secret_bytes

        if args.base64:
            secret_content = _encode_base64(secret_bytes)
        else:
            secret_content = secret_bytes

        _write_output(secret_content, args.output_secret, secure=True)

        if not args.output_secret:
            print(
                f"Generated {len(secret_bytes)}-byte secret for {args.algorithm}",
                file=sys.stderr,
            )

    else:
        if args.output_secret:
            _error_exit(
                "Asymmetric algorithms don't use secrets. Use --output-private and --output-public instead."
            )

        if not args.output_private and not args.output_public:
            _error_exit(
                "For asymmetric algorithms, specify at least --output-private or --output-public"
            )

        assert asym_alg is not None  # Type checker hint
        public_key, private_key = asym_alg.generate_keypair()

        if args.format == "PEM":
            encoding = serialization.Encoding.PEM
        else:
            encoding = serialization.Encoding.DER

        # Save private key
        if args.output_private:
            private_pem = private_key.private_bytes(
                encoding=encoding,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            _write_output(private_pem, args.output_private, secure=True)

        # Save public key
        if args.output_public:
            public_pem = public_key.public_bytes(
                encoding=encoding,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            _write_output(public_pem, args.output_public, public_key=True)

        print(
            f"Generated {args.algorithm} key pair in {args.format} format",
            file=sys.stderr,
        )


def sign() -> None:
    """Sign data using JWS algorithms."""
    parser = argparse.ArgumentParser(
        description="Sign data using JWS algorithms",
        epilog="""
Examples:
  # Sign with HMAC using secret from file
  echo "Hello World" | jws-sign --algorithm HS256 --secret secret.key
  
  # Sign with RSA using private key from file
  jws-sign --algorithm RS256 --private-key private.pem --input message.txt --output signature.bin
  
  # Sign text directly with base64 output
  jws-sign --algorithm ES256 --private-key private.pem --text "Hello World" --base64
  
  # Sign text with URL-safe base64 output  
  jws-sign --algorithm HS256 --secret secret.key --text "Hello World" --url-safe
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--algorithm",
        "-a",
        required=True,
        choices=[alg.name for alg in SymmetricAlgorithm]
        + [alg.name for alg in AsymmetricAlgorithm],
        help="Algorithm to use for signing",
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--input",
        "-i",
        type=Path,
        help="Input file to sign (use stdin if not specified)",
    )
    input_group.add_argument("--text", "-t", help="Text to sign directly")

    # Key/secret options
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--secret", "-s", type=Path, help="Secret file for symmetric algorithms"
    )
    key_group.add_argument(
        "--private-key",
        "-p",
        type=Path,
        help="Private key file for asymmetric algorithms",
    )

    parser.add_argument("--password", help="Password for encrypted private key")

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file for signature (use stdout if not specified)",
    )

    parser.add_argument(
        "--base64", "-b", action="store_true", help="Encode signature in base64"
    )

    parser.add_argument(
        "--url-safe",
        action="store_true",
        help="Use URL-safe base64 encoding (implies --base64)",
    )

    args = parser.parse_args()

    # Determine algorithm type
    sym_alg = None
    asym_alg = None

    try:
        sym_alg = SymmetricAlgorithm[args.algorithm]
        is_symmetric = True
    except KeyError:
        try:
            asym_alg = AsymmetricAlgorithm[args.algorithm]
            is_symmetric = False
        except KeyError:
            _error_exit(f"Unknown algorithm: {args.algorithm}")

    # Validate key/secret arguments
    if is_symmetric and args.private_key:
        _error_exit("Symmetric algorithms require --secret, not --private-key")
    if not is_symmetric and args.secret:
        _error_exit("Asymmetric algorithms require --private-key, not --secret")

    # Read input data
    try:
        if args.input:
            payload = args.input.read_bytes()
        elif args.text:
            payload = args.text.encode("utf-8")
        else:
            payload = sys.stdin.buffer.read()
    except Exception as e:
        _error_exit(f"Failed to read input: {e}")

    # Sign the payload
    try:
        if is_symmetric:
            assert sym_alg is not None  # Type checker hint
            signature = sym_alg.sign(args.secret, payload)
        else:
            assert asym_alg is not None  # Type checker hint
            signature = asym_alg.sign(args.private_key, payload, password=args.password)
    except Exception as e:
        _error_exit(f"Failed to sign: {e}")

    # Encode signature if requested
    if args.base64 or args.url_safe:
        signature_output = _encode_base64(signature, args.url_safe)
    else:
        signature_output = signature

    # Write output
    _write_output(signature_output, args.output)

    if not args.output:
        print(f"Signed {len(payload)} bytes with {args.algorithm}", file=sys.stderr)


def verify() -> None:
    """Verify signatures using JWS algorithms."""
    parser = argparse.ArgumentParser(
        description="Verify signatures using JWS algorithms",
        epilog="""
Examples:
  # Verify HMAC signature
  jws-verify --algorithm HS256 --secret secret.key --input message.txt --signature signature.bin
  
  # Verify RSA signature with base64-encoded signature
  jws-verify --algorithm RS256 --public-key public.pem --text "Hello World" --signature-base64 "base64sig..."
  
  # Verify using stdin for data and signature file
  echo "Hello World" | jws-verify --algorithm ES256 --public-key public.pem --signature signature.bin
  
  # Verify with URL-safe base64-encoded signature
  jws-verify --algorithm HS256 --secret secret.key --text "Hello World" --signature-urlsafe "urlsafe-base64sig..."
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--algorithm",
        "-a",
        required=True,
        choices=[alg.name for alg in SymmetricAlgorithm]
        + [alg.name for alg in AsymmetricAlgorithm],
        help="Algorithm to use for verification",
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--input",
        "-i",
        type=Path,
        help="Input file to verify (use stdin if not specified)",
    )
    input_group.add_argument("--text", "-t", help="Text to verify directly")

    # Key/secret options
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "--secret", "-s", type=Path, help="Secret file for symmetric algorithms"
    )
    key_group.add_argument(
        "--public-key",
        "-p",
        type=Path,
        help="Public key file for asymmetric algorithms",
    )

    # Signature options
    sig_group = parser.add_mutually_exclusive_group(required=True)
    sig_group.add_argument("--signature", "-g", type=Path, help="Signature file")
    sig_group.add_argument("--signature-base64", "-b", help="Base64-encoded signature")
    sig_group.add_argument(
        "--signature-urlsafe", help="URL-safe base64-encoded signature"
    )

    args = parser.parse_args()

    # Determine algorithm type
    sym_alg = None
    asym_alg = None

    try:
        sym_alg = SymmetricAlgorithm[args.algorithm]
        is_symmetric = True
    except KeyError:
        try:
            asym_alg = AsymmetricAlgorithm[args.algorithm]
            is_symmetric = False
        except KeyError:
            _error_exit(f"Unknown algorithm: {args.algorithm}")

    # Validate key/secret arguments
    if is_symmetric and args.public_key:
        _error_exit("Symmetric algorithms require --secret, not --public-key")
    if not is_symmetric and args.secret:
        _error_exit("Asymmetric algorithms require --public-key, not --secret")

    # Read input data
    try:
        if args.input:
            payload = args.input.read_bytes()
        elif args.text:
            payload = args.text.encode("utf-8")
        else:
            payload = sys.stdin.buffer.read()
    except Exception as e:
        _error_exit(f"Failed to read input: {e}")

    # Read signature
    try:
        if args.signature:
            signature = args.signature.read_bytes()
        elif args.signature_base64:
            signature = _decode_base64(args.signature_base64, url_safe=False)
        else:  # args.signature_urlsafe
            signature = _decode_base64(args.signature_urlsafe, url_safe=True)
    except Exception as e:
        _error_exit(f"Failed to read signature: {e}")

    # Verify the signature
    try:
        if is_symmetric:
            assert sym_alg is not None  # Type checker hint
            is_valid = sym_alg.verify(args.secret, payload, signature)
        else:
            assert asym_alg is not None  # Type checker hint
            is_valid = asym_alg.verify(args.public_key, payload, signature)
    except Exception as e:
        _error_exit(f"Failed to verify: {e}")

    # Output result
    if is_valid:
        print("✓ Signature is valid")
        sys.exit(0)
    else:
        print("✗ Signature is invalid")
        sys.exit(1)


if __name__ == "__main__":
    import sys

    # Determine which function to call based on script name or first argument
    script_name = Path(sys.argv[0]).name

    if script_name == "jws-gen-keys" or "gen-keys" in script_name:
        generate_keys()
    elif script_name == "jws-sign" or "sign" in script_name:
        sign()
    elif script_name == "jws-verify" or "verify" in script_name:
        verify()
    elif len(sys.argv) > 1:
        command = sys.argv[1]
        # Remove the command from argv so the individual functions can parse their arguments
        sys.argv = [sys.argv[0]] + sys.argv[2:]

        if command in ("gen-keys", "generate-keys"):
            generate_keys()
        elif command == "sign":
            sign()
        elif command == "verify":
            verify()
        else:
            print(f"Error: Unknown command '{command}'")
            print("Available commands: gen-keys, sign, verify")
            sys.exit(1)
    else:
        print("Usage: python -m jws_algorithms.cli <command>")
        print("Commands: gen-keys, sign, verify")
        print("Or use the installed scripts: jws-gen-keys, jws-sign, jws-verify")
        sys.exit(1)
