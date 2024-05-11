# Fast Verify

Support Rails style MessageVerifier for Python.

## Install

```bash
pip install fast-verify
```

## Usage

```python
from fast_verify import CachingKeyGenerator, MessageVerifier

secret = b"aaa"
key_gen = CachingKeyGenerator(secret)
verifier = MessageVerifier(key_gen(b"purpose"))
verifier.read_message(verifier.create_message(b"haha"))
```

