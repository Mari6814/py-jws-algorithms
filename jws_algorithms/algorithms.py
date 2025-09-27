"""Implement the `SymmetricAlgorithm` and `AsymmetricAlgorithm` enums with methods to generate keys/secrets, sign data, and verify signatures."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa


@dataclass
class _Secret:
    """A simple wrapper for secret bytes. This is to avoid confusion with keys. If this doesn't exist, you might accidentally pass a secret to the signature or payload parameter."""

    secret_bytes: bytes

    def __repr__(self) -> str:
        return f"_Secret(secret_bytes='{self.secret_bytes.hex()}')"

    def __str__(self) -> str:
        """Return the secret as a latin-1 decoded string, which can natively represent all byte values."""
        return self.secret_bytes.decode("latin-1")


class SymmetricAlgorithm(Enum):
    """Lists the supported symmetric algorithms and provides methods to generate secrets, sign, and verify signatures.

    The algorithms provided here are the most common ones used in the context for JWTs/JWSs.
    """

    HS256 = "HMAC-SHA256"
    HS384 = "HMAC-SHA384"
    HS512 = "HMAC-SHA512"

    def generate_secret(self, num_bytes: int | None = None) -> _Secret:
        """Generate a random key for the algorithm.

        Args:
            num_bytes: The number of bytes to generate. If not provided, a sensible default will be used based on the algorithm. For HS256, the default is 32 bytes (256 bits). For HS384, it's 48 bytes (384 bits). For HS512, it's 64 bytes (512 bits).

        Returns:
            An instance of `_Secret` containing the generated secret bytes. Pass it as the first argument to the `sign` and `verify` methods. It only wraps your bytes to avoid confusion with payloads or signatures. You can extract the bytes using the `secret_bytes` attribute if you need to store it or use it elsewhere.

        """
        match self:
            case SymmetricAlgorithm.HS256:
                secret_bytes = secrets.token_bytes(num_bytes or 32)
            case SymmetricAlgorithm.HS384:
                secret_bytes = secrets.token_bytes(num_bytes or 48)
            case SymmetricAlgorithm.HS512:
                secret_bytes = secrets.token_bytes(num_bytes or 64)

        return _Secret(secret_bytes)

    def sign(
        self,
        secret: _Secret | bytes | Path | str,
        payload: bytes | str,
    ) -> bytes:
        """Sign payload using HMAC with the algorithm's hash function.

        Args:
            secret: The secret used to sign the payload. Can be a path to a file or be bytes with the secret. A `str` will be treated as utf-8 bytes. The `_Secret` is generated using the `generate_secret` method to wrap your bytes and is only there to avoid confusion with payloads or signatures.
            payload: The data to sign. A `str` payload will be treated as utf-8 encoded bytes.

        Returns:
            The HMAC signature as bytes. You can encode it as base64 or hex for easier transport.

        """
        match self:
            case SymmetricAlgorithm.HS256:
                hash_func = hashlib.sha256
            case SymmetricAlgorithm.HS384:
                hash_func = hashlib.sha384
            case SymmetricAlgorithm.HS512:
                hash_func = hashlib.sha512

        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        if isinstance(secret, Path):
            with secret.open("rb") as secret_file:
                secret = secret_file.read()
        elif isinstance(secret, str):
            secret = secret.encode("utf-8")
        elif isinstance(secret, _Secret):
            secret = secret.secret_bytes

        return hmac.new(secret, payload, hash_func).digest()

    def verify(
        self,
        secret: _Secret | bytes | Path | str,
        payload: bytes | str,
        signature: bytes,
    ) -> bool:
        """Verify HMAC signature of payload using the algorithm's hash function.

        Args:
            secret: The secret used to verify the signature. Can be a path to a file or be bytes with the secret. A `str` will be treated as utf-8 bytes. The `_Secret` is generated using the `generate_secret` method to wrap your bytes and is only there to avoid confusion with payloads or signatures.
            payload: The data that was signed. A `str` payload will be treated as utf-8 encoded bytes.
            signature: The signature to verify

        Returns:
            True if the signature is valid, False otherwise.

        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        if isinstance(secret, Path):
            with secret.open("rb") as secret_file:
                secret = secret_file.read()
        elif isinstance(secret, str):
            secret = secret.encode("utf-8")
        elif isinstance(secret, _Secret):
            secret = secret.secret_bytes

        expected_signature = self.sign(secret, payload)
        return hmac.compare_digest(expected_signature, signature)


class AsymmetricAlgorithm(Enum):
    """Lists the supported asymmetric algorithms and provides methods to generate key pairs, sign, and verify signatures.

    The algorithms provided here are the most common ones used for JWTs/JWSs.
    """

    RS256 = "RSA-SHA256"
    RS384 = "RSA-SHA384"
    RS512 = "RSA-SHA512"

    ES256 = "ECDSA-SHA256"
    ES384 = "ECDSA-SHA384"
    ES512 = "ECDSA-SHA512"

    PS256 = "RSA-PSS-SHA256"
    PS384 = "RSA-PSS-SHA384"
    PS512 = "RSA-PSS-SHA512"

    EdDSA = "EdDSA"

    def generate_keypair(
        self,
    ) -> (
        tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]
        | tuple[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]
        | tuple[ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey]
        | tuple[ed448.Ed448PublicKey, ed448.Ed448PrivateKey]
    ):
        """Generate a public/private key pair for the algorithm.

        Encryption is not supported here. Please use external tools for that.

        Returns:
            A tuple of (public_key, private_key) suitable for the algorithm.

        """
        match self:
            case (
                AsymmetricAlgorithm.RS256
                | AsymmetricAlgorithm.RS384
                | AsymmetricAlgorithm.RS512
            ):
                rsa_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                rsa_public_key = rsa_private_key.public_key()

                return rsa_public_key, rsa_private_key
            case (
                AsymmetricAlgorithm.ES256
                | AsymmetricAlgorithm.ES384
                | AsymmetricAlgorithm.ES512
            ):
                curve_map = {
                    AsymmetricAlgorithm.ES256: ec.SECP256R1(),
                    AsymmetricAlgorithm.ES384: ec.SECP384R1(),
                    AsymmetricAlgorithm.ES512: ec.SECP521R1(),
                }
                es_private_key = ec.generate_private_key(curve_map[self])
                return es_private_key.public_key(), es_private_key
            case (
                AsymmetricAlgorithm.PS256
                | AsymmetricAlgorithm.PS384
                | AsymmetricAlgorithm.PS512
            ):
                rsa_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                rsa_public_key = rsa_private_key.public_key()
                return rsa_public_key, rsa_private_key
            case AsymmetricAlgorithm.EdDSA:
                ed25519_private_key = ed25519.Ed25519PrivateKey.generate()
                return ed25519_private_key.public_key(), ed25519_private_key

    def sign(
        self,
        private_key: (
            rsa.RSAPrivateKey
            | ec.EllipticCurvePrivateKey
            | ed25519.Ed25519PrivateKey
            | ed448.Ed448PrivateKey
            | Path
            | str
            | bytes
        ),
        payload: bytes | str,
        password: bytes | str | None = None,
    ) -> bytes:
        """Sign payload using the asymmetric algorithm with the provided private key.

        Args:
            private_key: The private key used to sign the payload. Can be a path to PEM or DER encoded file or be bytes with a PEM or DER encoded private key. A `str` will be treated as utf-8 bytes.
            payload: The data to sign. A `str` payload will be treated as utf-8 encoded bytes.
            password: The password to decrypt the private key, if applicable. A `str` password will be treated as utf-8 bytes.

        Returns:
            The signature as bytes. You can encode it as base64 or hex for easier transport.

        Raises:
            ValueError: If the algorithm or key type is unsupported.
            TypeError: If the loaded key is not a supported type.

        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        if isinstance(private_key, (Path, str, bytes)):
            private_key = self._load_pk(private_key, password=password)

        match self:
            case (
                AsymmetricAlgorithm.RS256
                | AsymmetricAlgorithm.RS384
                | AsymmetricAlgorithm.RS512
            ) if isinstance(private_key, rsa.RSAPrivateKey):
                return private_key.sign(
                    data=payload,
                    padding=padding.PKCS1v15(),
                    algorithm=self._get_hash_algorithm(),
                )
            case (
                AsymmetricAlgorithm.ES256
                | AsymmetricAlgorithm.ES384
                | AsymmetricAlgorithm.ES512
            ) if isinstance(private_key, ec.EllipticCurvePrivateKey):
                return private_key.sign(
                    data=payload,
                    signature_algorithm=ec.ECDSA(self._get_hash_algorithm()),
                )
            case (
                AsymmetricAlgorithm.PS256
                | AsymmetricAlgorithm.PS384
                | AsymmetricAlgorithm.PS512
            ) if isinstance(private_key, rsa.RSAPrivateKey):
                return private_key.sign(
                    data=payload,
                    padding=padding.PSS(
                        mgf=padding.MGF1(self._get_hash_algorithm()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    algorithm=self._get_hash_algorithm(),
                )
            case AsymmetricAlgorithm.EdDSA if isinstance(
                private_key,
                (ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey),
            ):
                return private_key.sign(payload)
        raise ValueError("Unsupported algorithm or key type.")

    def verify(
        self,
        public_key: (
            rsa.RSAPublicKey
            | ec.EllipticCurvePublicKey
            | ed25519.Ed25519PublicKey
            | ed448.Ed448PublicKey
            | Path
            | str
            | bytes
        ),
        payload: bytes | str,
        signature: bytes,
        force_padding: padding.AsymmetricPadding | None = None,
        force_algorithm: ec.EllipticCurveSignatureAlgorithm | None = None,
    ) -> bool:
        """Verify signature of payload using the asymmetric algorithm with the provided public key.

        Args:
            public_key: The public key used to verify the signature. Can be a path to PEM or DER encoded file or be in-memory bytes with a PEM or DER encoded public key. A `str` will be treated as utf-8 bytes.
            payload: The data that was signed. A `str` payload will be treated as utf-8 encoded bytes.
            signature: The signature to verify.
            force_padding: You can ignore this if you don't know what this is. Optional padding to use for verification when the algorithm requires it. Uses PKCS1v15 for RSA and PSS for RSASSA-PSS if not specified.
            force_algorithm: You can ignore this if you don't know what this is. Optional signature algorithm to use for verification when using ECDSA. Uses ECDSA if not specified.

        Returns:
            True if the signature is valid, False otherwise.

        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        if isinstance(public_key, (Path, str, bytes, bytearray)):
            public_key = self._load_pubkey(public_key)

        try:
            match self:
                case (
                    AsymmetricAlgorithm.RS256
                    | AsymmetricAlgorithm.RS384
                    | AsymmetricAlgorithm.RS512
                ) if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        signature,
                        data=payload,
                        padding=force_padding or padding.PKCS1v15(),
                        algorithm=self._get_hash_algorithm(),
                    )
                case (
                    AsymmetricAlgorithm.ES256
                    | AsymmetricAlgorithm.ES384
                    | AsymmetricAlgorithm.ES512
                ) if isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        signature,
                        data=payload,
                        signature_algorithm=force_algorithm
                        or ec.ECDSA(self._get_hash_algorithm()),
                    )
                case (
                    AsymmetricAlgorithm.PS256
                    | AsymmetricAlgorithm.PS384
                    | AsymmetricAlgorithm.PS512
                ) if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        signature,
                        data=payload,
                        padding=force_padding
                        or padding.PSS(
                            mgf=padding.MGF1(self._get_hash_algorithm()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        algorithm=self._get_hash_algorithm(),
                    )
                case AsymmetricAlgorithm.EdDSA if isinstance(
                    public_key,
                    (ed25519.Ed25519PublicKey | ed448.Ed448PublicKey),
                ):
                    public_key.verify(signature, payload)
                case _:
                    raise ValueError("Unsupported algorithm or key type.")
        except InvalidSignature:
            return False
        return True

    def _get_hash_algorithm(self) -> hashes.HashAlgorithm:
        """Determine which hash algorithm to use for this algorithm."""
        match self:
            case (
                AsymmetricAlgorithm.RS256
                | AsymmetricAlgorithm.PS256
                | AsymmetricAlgorithm.ES256
            ):
                return hashes.SHA256()
            case (
                AsymmetricAlgorithm.RS384
                | AsymmetricAlgorithm.PS384
                | AsymmetricAlgorithm.ES384
            ):
                return hashes.SHA384()
            case (
                AsymmetricAlgorithm.RS512
                | AsymmetricAlgorithm.PS512
                | AsymmetricAlgorithm.ES512
                | AsymmetricAlgorithm.EdDSA
            ):
                return hashes.SHA512()

    @staticmethod
    def _load_pubkey(
        public_key: bytes | Path | str,
    ) -> (
        rsa.RSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey
    ):
        """Load a public key from a file or in-memory bytes.

        Args:
            public_key: The target has to be DER or PEM encoded. `Path` will load the bytes from disk. `bytes` and `str` is for in-memory keys. A `str` will be treated as utf-8 bytes.

        Returns:
            The loaded public key object.

        Raises:
            TypeError: If the loaded key is not a supported type.
            ValueError: If the key could not be loaded.

        """
        if isinstance(public_key, Path):
            with public_key.open("rb") as key_file:
                public_key = key_file.read()
        elif isinstance(public_key, str):
            public_key = public_key.encode("utf-8")

        if isinstance(public_key, (bytes, bytearray)):
            try:
                pubkey = serialization.load_pem_public_key(public_key)
            except ValueError:
                try:
                    pubkey = serialization.load_der_public_key(public_key)
                except ValueError:
                    pubkey = serialization.load_ssh_public_key(public_key)

            if not isinstance(
                pubkey,
                (
                    rsa.RSAPublicKey,
                    ec.EllipticCurvePublicKey,
                    ed25519.Ed25519PublicKey,
                    ed448.Ed448PublicKey,
                ),
            ):
                raise TypeError(
                    f"Invalid public key type: {type(pubkey)}. We only support RSA, EC, Ed25519, and Ed448 keys.",
                )

            return pubkey

        raise ValueError("Unable to determine public key.")

    @staticmethod
    def _load_pk(
        private_key: bytes | Path | str,
        password: bytes | str | None = None,
    ) -> (
        rsa.RSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey
    ):
        """Load a private key from PEM or DER format.

        Args:
            private_key: The target has to be DER or PEM encoded. `bytes` and `str` are for in-memory keys. `Path` will load the bytes from disk. A `str` will be treated as utf-8 bytes.
            password: The password to decrypt the private key, if applicable. A `str` will be treated as utf-8 bytes.

        Raises:
            TypeError: If the loaded key is not a supported type.
            ValueError: If the key could not be loaded.

        Returns:
            The loaded private key object.

        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        if isinstance(private_key, Path):
            with private_key.open("rb") as key_file:
                private_key = key_file.read()
        elif isinstance(private_key, str):
            private_key = private_key.encode("utf-8")

        if isinstance(private_key, (bytes, bytearray)):
            try:
                pk = serialization.load_pem_private_key(private_key, password=password)
            except ValueError:
                try:
                    pk = serialization.load_der_private_key(
                        private_key,
                        password=password,
                    )
                except ValueError:
                    pk = serialization.load_ssh_private_key(
                        private_key,
                        password=password,
                    )

            if not isinstance(
                pk,
                (
                    rsa.RSAPrivateKey,
                    ec.EllipticCurvePrivateKey,
                    ed25519.Ed25519PrivateKey,
                    ed448.Ed448PrivateKey,
                ),
            ):
                raise TypeError(
                    f"Invalid private key type: {type(pk)}. We only support RSA, EC, Ed25519, and Ed448 keys.",
                )

            return pk

        raise ValueError("Unable to determine private key.")
