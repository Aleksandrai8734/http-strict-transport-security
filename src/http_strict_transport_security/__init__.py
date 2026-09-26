"""HTTP Strict Transport Security header parser.

Exports:
    HSTSPolicy: parsed result with max_age (int|None), include_sub_domains (bool),
               preload (bool).
    parse_hsts: parse a raw HSTS header value into an HSTSPolicy.
"""

from .core import HSTSPolicy, parse_hsts

__all__ = ["HSTSPolicy", "parse_hsts"]
