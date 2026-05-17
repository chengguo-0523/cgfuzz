import itertools
from typing import Iterable, List


DEFAULT_BUILTIN_WORDS = [
    "admin",
    "administrator",
    "root",
    "test",
    "guest",
    "dev",
    "api",
    "login",
    "upload",
    "debug",
    "system",
    "backup",
]

COMMON_SUFFIXES = [
    "",
    "1",
    "01",
    "123",
    "1234",
    "2024",
    "2025",
    "2026",
    "@123",
    "_test",
    "_dev",
    "!",
]

LEET_MAP = str.maketrans(
    {
        "a": "4",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "5",
        "t": "7",
    }
)


def unique_preserve(items: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for item in items:
        value = item.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def parse_dictionary_text(text: str) -> List[str]:
    raw_lines = text.replace(",", "\n").splitlines()
    return unique_preserve(raw_lines)


def build_builtin_dictionary() -> List[str]:
    return list(DEFAULT_BUILTIN_WORDS)


def build_mutation_dictionary(
    seed_text: str,
    append_numbers: bool = True,
    include_case_variants: bool = True,
    include_leet: bool = True,
    include_common_suffixes: bool = True,
    max_number: int = 30,
) -> List[str]:
    seeds = unique_preserve(seed_text.replace(",", "\n").splitlines())
    generated: List[str] = []

    for seed in seeds:
        variants = [seed]
        if include_case_variants:
            variants.extend([seed.lower(), seed.upper(), seed.capitalize()])
        if include_leet:
            variants.append(seed.lower().translate(LEET_MAP))
        variants = unique_preserve(variants)

        generated.extend(variants)

        if append_numbers:
            for variant in variants:
                generated.extend(f"{variant}{number}" for number in range(max_number + 1))

        if include_common_suffixes:
            for variant, suffix in itertools.product(variants, COMMON_SUFFIXES):
                generated.append(f"{variant}{suffix}")

    return unique_preserve(generated)


def build_mask_dictionary(
    use_lower: bool = True,
    use_upper: bool = False,
    use_digits: bool = True,
    use_symbols: bool = False,
    min_length: int = 1,
    max_length: int = 2,
    prefix: str = "",
    suffix: str = "",
    limit: int = 500,
) -> List[str]:
    charsets = []
    if use_lower:
        charsets.append("abcdefghijklmnopqrstuvwxyz")
    if use_upper:
        charsets.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if use_digits:
        charsets.append("0123456789")
    if use_symbols:
        charsets.append("._-@")

    alphabet = "".join(charsets)
    if not alphabet:
        return []

    results: List[str] = []
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(alphabet, repeat=length):
            results.append(f"{prefix}{''.join(combo)}{suffix}")
            if len(results) >= limit:
                return results
    return results
