# http-strict-transport-security

A small, zero-dependency Python parser for the HTTP Strict Transport Security
(HSTS) response header. Returns the three values a client actually needs:
`max_age`, `include_sub_domains`, and `preload`.

## Usage

```python
from http_strict_transport_security import parse_hsts

policy = parse_hsts("max-age=63072000; includeSubDomains; preload")
print(policy.max_age)             # 63072000
print(policy.include_sub_domains)  # True
print(policy.preload)              # True
```

## Why this exists

HSTS parsing is simple enough that pulling in a general-purpose HTTP header
library is overkill, and annoying enough (case-insensitive tokens, optional
directives, arbitrary ordering, quoted-string tolerance) that hand-rolling it
inline in every project is a bug source. This library is the one file you would
have written yourself.

The trade-off: we parse permissively. Unknown or malformed directives are
silently ignored rather than raising, which mirrors browser behaviour but means
a typo'd directive will not surface as an error. If `max-age` is missing or
unparseable, `max_age` is `None`; callers are responsible for treating `None`
as "do not enforce". The `includeSubDomains` and `preload` flags carry no value
per the spec and are simply booleans.

## Edge case worth knowing

If multiple `max-age` directives appear in the same header, the **last** one
wins. This is a deliberate choice; if your code depends on a specific one, send
a clean header.

## Running the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

