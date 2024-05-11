from fast_verify import CachingKeyGenerator, MessageVerifier, InvalidSignature
import pytest  # type: ignore


def test_match():
    secret = b"aaa"
    key_gen = CachingKeyGenerator(secret)
    verifier = MessageVerifier(key_gen(b"purpose"))
    verifier.read_message(verifier.create_message(b"haha"))


def test_mismatch():
    with pytest.raises(InvalidSignature) as exc_info:
        secret = b"aaa"
        key_gen = CachingKeyGenerator(secret)
        verifier = MessageVerifier(key_gen(b"purpose"))
        verifier.read_message(verifier.create_message(b"haha") + b"b")
