import base64
from functools import cache, cached_property
from typing import ClassVar, Protocol, runtime_checkable
from hmac import compare_digest, HMAC
from hashlib import pbkdf2_hmac


class InvalidSignature(Exception): ...


def secure_compare(a: bytes, b: bytes) -> bool:
    return len(a) == len(b) and compare_digest(a, b)


@runtime_checkable
class KeyGenerator(Protocol):
    def __call__(self, salt: bytes, key_size: int = 64) -> bytes: ...


class BaseKeyGenerator:
    def __init__(
        self, secret: bytes, iterations: int = 2**16, digest: str = "SHA1"
    ) -> None:
        self._secret = secret
        self._iterations = iterations
        self._digest = digest

    def __call__(self, salt: bytes, key_size: int = 64) -> bytes:
        return pbkdf2_hmac(
            hash_name=self._digest,
            password=self._secret,
            salt=salt,
            dklen=key_size,
            iterations=self._iterations,
        )


class CachingKeyGenerator:
    def __init__(
        self, secret: bytes, iterations: int = 2**16, digest: str = "SHA1"
    ) -> None:
        self._impl = BaseKeyGenerator(
            secret=secret, iterations=iterations, digest=digest
        )

    @cache
    def __call__(self, salt: bytes, key_size: int = 64) -> bytes:
        return self._impl(salt, key_size)


class MessageVerifier:
    SEPARATOR: ClassVar[bytes] = "--".encode()
    SEPARATOR_LENGTH: ClassVar[int] = len(SEPARATOR)

    def __init__(self, secret: bytes, digest: str = "SHA1") -> None:
        self._secret = secret
        self._digest = digest

    def create_message(self, value: bytes):
        return self._sign_encoded(self._encode(value))

    def read_message(self, message: bytes):
        return self._decode(self._extract_encoded(message))

    def _encode(self, value: bytes) -> bytes:
        return base64.b64encode(value)

    def _decode(self, value: bytes) -> bytes:
        return base64.b64decode(value)

    def _sign_encoded(self, encoded: bytes) -> bytes:
        digest = self._generate_digest(encoded)
        return encoded + MessageVerifier.SEPARATOR + digest

    def _extract_encoded(self, signed: bytes) -> bytes:
        if separator_index := self.separator_index_for(signed):
            encoded = signed[0:separator_index]
            offset = separator_index + MessageVerifier.SEPARATOR_LENGTH
            digest = signed[offset : offset + self._digest_length_in_hex]
        else:
            raise InvalidSignature("mismatched signed")
        if not self._is_digest_matches_data(digest, encoded):
            raise InvalidSignature("mismatched signed")
        return encoded

    def _is_digest_matches_data(self, digest: bytes, encoded: bytes) -> bool:
        return secure_compare(digest, self._generate_digest(encoded))

    def separator_index_for(self, signed_message: bytes) -> int | None:
        index = (
            len(signed_message)
            - self._digest_length_in_hex
            - MessageVerifier.SEPARATOR_LENGTH
        )
        if index < 0 or not self._is_separator_at(signed_message, index):
            return None
        return index

    def _generate_digest(self, data: bytes) -> bytes:
        h = HMAC(key=self._secret, msg=data, digestmod=self._digest)
        return h.hexdigest().encode()

    @cached_property
    def _digest_length_in_hex(self) -> int:
        return HMAC(key=self._secret, digestmod=self._digest).digest_size * 2

    def _is_separator_at(self, signed_message: bytes, index: int) -> bool:
        return (
            signed_message[index : index + MessageVerifier.SEPARATOR_LENGTH]
            == MessageVerifier.SEPARATOR
        )
