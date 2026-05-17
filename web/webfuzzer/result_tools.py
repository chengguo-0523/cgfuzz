import difflib
import re


def normalize_response_text(text: str) -> str:
    lowered = text.lower()
    lowered = re.sub(r"\s+", " ", lowered)
    lowered = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", lowered)
    lowered = re.sub(r"\b\d{4,}\b", "<num>", lowered)
    return lowered[:4000].strip()


def calculate_similarity(left: str, right: str) -> int:
    if not left and not right:
        return 100
    ratio = difflib.SequenceMatcher(None, left, right).ratio()
    return int(ratio * 100)
