"""Shannon entropy, used to spot high-randomness strings."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character in `text`."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def looks_random(
    text: str,
    *,
    min_length: int = 20,
    threshold: float = 3.5,
    min_classes: int = 2,
) -> bool:
    """Heuristic: long enough, random enough, and not a single repeated class.

    `min_classes` guards against strings like ``aaaaaaaaaaaaaaaaaaaa`` which have
    zero entropy anyway, and against long runs of one character class.
    """
    if len(text) < min_length:
        return False
    # A secret is a single token. Anything with whitespace is prose, not a key.
    if any(ch.isspace() for ch in text):
        return False
    classes = sum(
        [
            any(c.islower() for c in text),
            any(c.isupper() for c in text),
            any(c.isdigit() for c in text),
            any(not c.isalnum() for c in text),
        ]
    )
    if classes < min_classes:
        return False
    return shannon_entropy(text) >= threshold
