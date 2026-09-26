"""Parser for the HTTP Strict Transport Security response header.

RFC 6797 section 6.1 defines the ABNF:

    Strict-Transport-Security = "max-age" delta-seconds ";" "max-age" delta-seconds
                                [ ";" "includeSubDomains" ]
                                [ ";" "preload" ]

with the note that the list MAY be in any order, and directives are
optional except that at least one max-age is required for the header to
be considered effective. We take a deliberately permissive stance:
we parse what we can, ignore what we cannot, and surface the pieces a
client actually needs to make policy decisions.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class HSTSPolicy:
    """Parsed representation of an HSTS header.

    max_age is None when no syntactically valid max-age directive is present.
    include_sub_domains and preload are False unless the corresponding token
    is present; per the spec, these directives carry no value.
    """

    max_age: Optional[int]
    include_sub_domains: bool = False
    preload: bool = False


def _strip_quotes(value: str) -> str:
    """Remove one matched pair of surrounding quotes.

    RFC 7230 says quoted-string is a legitimate form for some directive
    values; HSTS does not use quotes for max-age, but being tolerant here
    avoids failing on a misconfigured but unambiguous header.
    """
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def parse_hsts(header: str) -> HSTSPolicy:
    """Parse a raw HSTS header value.

    Directives are split on ';', trimmed, and matched case-insensitively.
    Unknown or malformed directives are ignored rather than raising; this
    matches browser behaviour and keeps callers from losing valid parts
    of a header because one directive was malformed.

    If multiple max-age directives appear, the last one wins, mirroring
    common header-parsing conventions.
    """
    if not isinstance(header, str):
        raise TypeError("header must be a string")

    max_age: Optional[int] = None
    include_sub_domains = False
    preload = False

    for raw in header.split(";"):
        item = raw.strip()
        if not item:
            continue

        # Split only on the first '=' so values containing '=' survive.
        if "=" in item:
            name, _, value = item.partition("=")
            name = name.strip()
            value = _strip_quotes(value.strip())
        else:
            name = item.strip()
            value = ""

        lower = name.lower()
        if lower == "max-age":
            # int() raises ValueError on non-numeric input; we drop the
            # directive rather than failing the whole parse.
            try:
                max_age = int(value)
            except ValueError:
                continue
        elif lower == "includesubdomains":
            include_sub_domains = True
        elif lower == "preload":
            preload = True
        # Anything else: deliberately ignored.

    return HSTSPolicy(
        max_age=max_age,
        include_sub_domains=include_sub_domains,
        preload=preload,
    )
