"""Provides easy to-use access to the algorithms commonly used for JSON Web Tokens (JWTs) / JSON Web Signatures (JWSs).

This module exposes two main classes: `AsymmetricAlgorithm` and `SymmetricAlgorithm`. Each enum lists the supported algorithms and provides methods to generate keys/secrets, sign data, and verify signatures.
"""

from .algorithms import (
    AsymmetricAlgorithm,
    SymmetricAlgorithm,
)

__all__ = [
    "AsymmetricAlgorithm",
    "SymmetricAlgorithm",
]
