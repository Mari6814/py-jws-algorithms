[![Test](https://github.com/Mari6814/py-jws-algorithms/actions/workflows/test.yml/badge.svg)](https://github.com/Mari6814/py-jws-algorithms/actions/workflows/test.yml)
[![Coverage](https://github.com/Mari6814/py-jws-algorithms/raw/main/badges/coverage.svg)](https://github.com/Mari6814/py-jws-algorithms/raw/main/badges/coverage.svg)
[![Versions](https://github.com/Mari6814/py-jws-algorithms/raw/main/badges/python-versions.svg)](https://github.com/Mari6814/py-jws-algorithms/raw/main/badges/python-versions.svg)

# Introduction

A simple library for signing and verifying messages using common JWS (JSON Web Signature) algorithms without the overhead of a full JWT/JWS library or a lot of setup and reading documentation when you do not need JWT/JWS.

This library provides two enums:

- **`SymmetricAlgorithm`**: for symmetric algorithms like HMAC, where the same secret is used for signing and verifying.
- **`AsymmetricAlgorithm`**: for asymmetric algorithms like RSA and ECDSA, where a private key is used for signing and a public key is used for verification.

Select the algorithm you want to use from the enum, then call its `sign` and `verify` methods, or if you still need a key `generate_secret` or `generate_keypair` depending on the algorithm.

# Installation

You can install the package via pip:

```bash
pip install jws-algorithms
```

# Basic Usage

Symmetric algorithms use shared _secrets_ that are simple random byte strings:

```python
from jws_algorithms import SymmetricAlgorithm

# Our message we want to sign and verify using HMAC-SHA256
message = b"Hello, World!"

# Generate a new secret random bytes
key = SymmetricAlgorithm.HS256.generate_secret()

# Sign the message
signature = SymmetricAlgorithm.HS256.sign(key, message)

# Verify the signature
assert SymmetricAlgorithm.HS256.verify(key, message, signature)
```

For more security, asymmetric algorithms use a _private key_ to sign messages and a _public key_ to verify signatures:

```python
from jws_algorithms import AsymmetricAlgorithm

# Our message we want to sign and verify using RSA-SHA256
message = b"Hello, World!"

# We need a public and private key pair
public_key, private_key = AsymmetricAlgorithm.RS256.generate_keypair()

# Sign the message with the private key
signature = AsymmetricAlgorithm.RS256.sign(private_key, message)

# Verify the signature with the public key
assert AsymmetricAlgorithm.RS256.verify(public_key, message, signature)
```

# Keys from files

The private keys can also be loaded from files by passing a `pathlib.Path` object to the loading functions.

```python
from pathlib import Path
from jws_algorithms import AsymmetricAlgorithm

# The message to sign using RSA-SHA256
message = b'Hello, World!'

# Sign with a private key loaded from a file
signature = AsymmetricAlgorithm.RS256.sign(
    Path('path/to/private_key.pem'),
    message
)

# Verify with a public key loaded from a file
assert AsymmetricAlgorithm.RS256.verify(
    Path('path/to/public_key.pem'),
    message,
    signature
)
```

# From raw text or environment

Keys can also be passed as raw text (often from environment variables) by calling the functions with a `str` or `bytes` instead of a `Path` or compiled representation of the `cryptography` package.

```python
import os
from jws_algorithms import AsymmetricAlgorithm

# The message to sign using RSA-SHA256
message = b'Hello, World!'

# Sign with a private key loaded from an environment variable
signature = AsymmetricAlgorithm.RS256.sign(os.environ['PRIVATE_KEY'], message)

# Verify with a public key loaded from an environment variable
assert AsymmetricAlgorithm.RS256.verify(os.environ['PUBLIC_KEY'], message, signature)
```

# Encrypted private keys

When loading private keys, you can provide an optional password if the private key is encrypted.
**Important**: You have to install with all optional dependencies or specifically the `encryption` extra to use this feature, as it depends on the `bcrypt` package.

```python
from pathlib import Path
from jws_algorithms import AsymmetricAlgorithm

# Sign with an encrypted private key loaded from a file
signature = AsymmetricAlgorithm.RS256.sign(
    Path('path/to/encrypted_private_key.pem'),
    b'Hello, World!',
    password='my_secret_password'
)

# Public keys are not encrypted, so no password is needed here
assert AsymmetricAlgorithm.RS256.verify(
    Path('path/to/public_key.pem'),
    b'Hello, World!',
    signature
)
```

# Using this enum in your own code

You can use the `SymmetricAlgorithm` and `AsymmetricAlgorithm` enums in your own code to select algorithms dynamically. For example, when your client has a signature, they can send the algorithm name along it and you can parse it using the enum:

```python
from jws_algorithms import SymmetricAlgorithm, AsymmetricAlgorithm

def index(request):
    alg_name = request.headers.get("X-Signature-Algorithm")
    algorithm = SymmetricAlgorithm[alg_name] if alg_name in SymmetricAlgorithm else AsymmetricAlgorithm[alg_name]
    message = request.body
    signature = request.headers.get("X-Signature")
    key = get_key_somehow(alg_name)  # Load the key from a database
    if not algorithm.verify(key, message, signature):
        raise ValueError("Invalid signature")
    # Process the request
```

# How to generate keys

In case you don't have keys yet, here are some examples of how to generate them.

## HMAC

Symmetric HMAC-SHA is just some random bytes:

```bash
# Using openssl
openssl rand -base64 32 > hmac_secret.key

# Using python
python -c "import os; print(os.urandom(32).hex())" > hmac_secret.key
```

## RSA

Using openssl:

```bash
# Generate a 2048-bit RSA private key in PEM format
openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key from the private key
openssl rsa -pubout -in rsa_private.pem -out rsa_public.pem
```

Using ssh-keygen:

```bash
# Generate a 2048-bit RSA private key in PEM format
ssh-keygen -t rsa -b 2048 -m PEM -f rsa_private.pem

# Extract the public key from the private key
ssh-keygen -y -f rsa_private.pem > rsa_public.pem
```

## ECDSA

Using openssl:

```bash
# Generate a private key for the P-256 curve in PEM format
openssl ecparam -name prime256v1 -genkey -noout -out ecdsa_private.pem

# Extract the public key from the private key
openssl ec -in ecdsa_private.pem -pubout -out ecdsa_public.pem
```

Using ssh-keygen:

```bash
# Generate a private key for the P-256 curve in PEM format
ssh-keygen -t ecdsa -b 256 -m PEM -f ecdsa_private.pem

# Extract the public key from the private key
ssh-keygen -y -f ecdsa_private.pem > ecdsa_public.pem
```

## EdDSA (Ed25519)

Using openssl:

```bash
# Generate an Ed25519 private key in PEM format
openssl genpkey -algorithm ED25519 -out ed25519_private.pem
# Extract the public key from the private key
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem
```

Using ssh-keygen:

```bash
# Generate an Ed25519 private key in PEM format
ssh-keygen -t ed25519 -m PEM -f ed25519_private.pem

# Extract the public key from the private key
ssh-keygen -y -f ed25519_private.pem > ed25519_public.pem
```
