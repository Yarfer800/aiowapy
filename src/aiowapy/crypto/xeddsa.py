"""XEdDSA: signing and verification for Curve25519 keys.

Implemented from the public XEdDSA specification: the signing key is the same
Curve25519 key used for Diffie-Hellman, so the protocol never needs a second key.
Arithmetic runs on Python integers; constant-time behaviour is not provided.
"""

from __future__ import annotations

import hashlib
import os

from aiowapy.crypto.primitives import CryptoError

FIELD = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, FIELD - 2, FIELD) % FIELD
_SQRT_M1 = pow(2, (FIELD - 1) // 4, FIELD)


class XEdDSAError(CryptoError):
    """Signing is impossible: the key or the format is invalid."""


def _recover_x(y: int, sign: int) -> int:
    numerator = (y * y - 1) % FIELD
    denominator = (_D * y * y + 1) % FIELD
    x_squared = numerator * pow(denominator, FIELD - 2, FIELD) % FIELD
    x = pow(x_squared, (FIELD + 3) // 8, FIELD)
    if (x * x - x_squared) % FIELD != 0:
        x = x * _SQRT_M1 % FIELD
    if (x * x - x_squared) % FIELD != 0:
        raise XEdDSAError("point is not on the curve")
    if x & 1 != sign:
        x = FIELD - x
    return x


_BASE_Y = 4 * pow(5, FIELD - 2, FIELD) % FIELD
_BASE_X = _recover_x(_BASE_Y, 0)
BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % FIELD)


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % FIELD
    b = (y1 + x1) * (y2 + x2) % FIELD
    c = 2 * t1 * t2 * _D % FIELD
    d = 2 * z1 * z2 % FIELD
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % FIELD, g * h % FIELD, f * g % FIELD, e * h % FIELD)


def _double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = x1 * x1 % FIELD
    b = y1 * y1 % FIELD
    c = 2 * z1 * z1 % FIELD
    d = -a % FIELD
    e = ((x1 + y1) * (x1 + y1) - a - b) % FIELD
    g = d + b
    f = g - c
    h = d - b
    return (e * f % FIELD, g * h % FIELD, f * g % FIELD, e * h % FIELD)


def _multiply(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    z_inv = pow(z, FIELD - 2, FIELD)
    x = x * z_inv % FIELD
    y = y * z_inv % FIELD
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _decode(encoded: bytes) -> tuple[int, int, int, int]:
    if len(encoded) != 32:
        raise XEdDSAError("a point must be encoded in 32 bytes")
    y = int.from_bytes(encoded, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % FIELD)


def _clamp(private: bytes) -> int:
    scalar = bytearray(private)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def montgomery_to_edwards(public_montgomery: bytes) -> bytes:
    """Map u to y = (u-1)/(u+1). Returns the Edwards encoding without the sign bit."""
    if len(public_montgomery) != 32:
        raise XEdDSAError("a public key must be 32 bytes")
    u = int.from_bytes(public_montgomery, "little") % FIELD
    y = (u - 1) * pow((u + 1) % FIELD, FIELD - 2, FIELD) % FIELD
    return y.to_bytes(32, "little")


def sign(private_montgomery: bytes, message: bytes, *, nonce: bytes | None = None) -> bytes:
    """Produce a 64-byte XEdDSA signature over `message`."""
    if len(private_montgomery) != 32:
        raise XEdDSAError("a private key must be 32 bytes")
    scalar = _clamp(private_montgomery)
    public_edwards = _encode(_multiply(BASE, scalar))
    random_scalar = int.from_bytes(os.urandom(64) if nonce is None else nonce, "little") % ORDER
    commitment = _encode(_multiply(BASE, random_scalar))
    challenge = (
        int.from_bytes(hashlib.sha512(commitment + public_edwards + message).digest(), "little")
        % ORDER
    )
    response = (random_scalar + challenge * scalar) % ORDER
    signature = bytearray(commitment + response.to_bytes(32, "little"))
    if public_edwards[31] & 0x80:
        signature[63] |= 0x80
    else:
        signature[63] &= 0x7F
    return bytes(signature)


def verify(public_montgomery: bytes, message: bytes, signature: bytes) -> bool:
    """Check a 64-byte XEdDSA signature against a Montgomery public key."""
    if len(public_montgomery) != 32 or len(signature) != 64:
        return False
    if not any(public_montgomery):
        return False
    u = int.from_bytes(public_montgomery, "little")
    if u >= FIELD:
        return False
    sign_bit = signature[63] >> 7
    try:
        edwards_y = montgomery_to_edwards(public_montgomery)
        point_a = _decode(edwards_y[:31] + bytes([edwards_y[31] | (sign_bit << 7)]))
        point_r = _decode(signature[:32])
    except XEdDSAError:
        return False
    response = int.from_bytes(signature[32:], "little") & ((1 << 255) - 1)
    if response >= ORDER:
        return False
    challenge = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + _encode(point_a) + message).digest(), "little"
        )
        % ORDER
    )
    left = _multiply(BASE, response)
    right = _add(point_r, _multiply(point_a, challenge))
    return _encode(left) == _encode(right)
