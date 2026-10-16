# EOX v0.6.4 — recursive helltest trace

Verified using the supplied `EOX_recursive_helltest(1).fukk` through the running HTTP API. The root is 6,623 bytes. All seven objects below have distinct SHA-256 identities. No automatic depth cap was used.

Ranges are half-open `[start, end)`. An embedded slice keeps its source coordinate system and absolute offsets within that source. A decoded member gets a new object coordinate system; its compressed or stored physical bytes are recorded separately. Session IDs in the JSON trace refer to this verification run.

| Object | Name | Type | Bytes | Relation | Decoded byte range | Physical storage range |
|---|---|---|---:|---|---|---|
| object-0 | `EOX_recursive_helltest(1).fukk` | Unknown / raw bytes | 6623 | root | object-0 [0, 6623) — 6623 bytes | Not a physical byte slice |
| object-1 | `EOX_recursive_helltest(1).fukk-offset-1838.zip` | ZIP container | 3650 | embedded | object-0 [1838, 5488) — 3650 bytes | object-0 [1838, 5488) — 3650 bytes |
| object-2 | `payload/layer.tar` | TAR container | 10240 | member | object-2 [0, 10240) — 10240 bytes | object-0 [1885, 5261) — 3376 bytes |
| object-3 | `containers/again.zip` | ZIP container | 905 | member | object-3 [0, 905) — 905 bytes | object-2 [6656, 7561) — 905 bytes |
| object-4 | `images/definitely_not_png.dat` | Raster image | 419 | member | object-4 [0, 419) — 419 bytes | object-3 [362, 686) — 324 bytes |
| object-5 | `images/definitely_not_png.dat-offset-119.zip` | ZIP container | 296 | embedded | object-4 [119, 415) — 296 bytes | object-4 [119, 415) — 296 bytes |
| object-6 | `basement/answer.json` | JSON / UTF-8 text | 208 | member | object-6 [0, 208) — 208 bytes | object-4 [169, 327) — 158 bytes |

## SHA-256 identities

- **object-0:** `e34554af2f367aaaf2083d9d1fb2e3ff0b771741f0d7ffe12bb8f944a79db4a0`
- **object-1:** `27e1f13d3c322e447ab10d40d72f8ca7753d48ed32b4c45b8927425304cb8283`
- **object-2:** `e0a07ebc0f55a8ac30df9339849c63cd69a91ac1f520959e8dec8e6638f342dc`
- **object-3:** `852f05ba87b06c08be3d79065faee76956f8637ae6409a85c89b5f9bd2b02d0f`
- **object-4:** `ecccf4b00c99958d6af4be6be2c9c73e4db72ec69efdef06e7d8be2b7ae5727d`
- **object-5:** `ccf05b944e0069a49901edca3cc41fda492b744da73da8e19af847bc4778cd0a`
- **object-6:** `df5f032f7be4efd4e5868fcecdee14c86f23044252fdb820d4d93ddc1e20909e`

## Terminal payload

```json
{
  "message": "EOX reached the basement.",
  "decoys": [
    "PK\\u0003\\u0004",
    "BM",
    "RIFF....WAVE",
    "%PDF-1.7",
    "MZ",
    "7zXZ"
  ],
  "rule": "These are strings, not embedded objects."
}
```

The original route using **Embedded → ZIP at TAR offset 6656** was also checked. It produces the same 905-byte `containers/again.zip` content, with TAR source range `[6656,7561)`. This is a legitimate alternate route. Reopening that ZIP at offset zero is blocked; its members are the next navigation step.

The 905-byte ZIP’s Embedded view lists its whole-object match as a non-clickable identity record. Direct typed and raw whole-file reopening both return an explicit recursion error and create no session object or temporary output.

The supplied file also has decoy ZIP/RIFF/PDF signatures, a separate PNG, a WAV with a BMP after its declared range, and nonterminal text/DXF members. These are separate branches; the table follows the path to `basement/answer.json`.

A literal complete self-copy inside an ordinary finite stored archive is not a straightforward fixture. Tests cover real cyclic TAR links (not followed), malformed ZIP pointers, and a real two-archive path with a mocked corrupt decoder returning exactly its ancestor’s bytes. The ancestry hash guard rejects that output and rolls back the reservation and temporary file.

Source SHA-256 remained unchanged. Full machine-readable provenance is in `examples/helltest-trace.json`.
