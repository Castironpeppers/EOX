# Validation — v0.6.4

- **99 unit/integration tests passed**. New coverage includes the frozen supplied
  helltest to its terminal JSON, the 905-byte self-reopening regression through
  typed/raw APIs, exact-range blocking, ancestry SHA-256 blocking, scan-time
  cycle warnings, a real 32-level ZIP chain (33 distinct objects), independent
  identical sibling payloads, shorter prefix identity with later embedded data,
  cyclic TAR links, malformed ZIP pointers, malformed provenance, direct-source
  mutation, actual-output length checks, cumulative byte/object reservations,
  rejection cleanup, and high-compression ZIP bomb refusal at the configured
  per-child bound.
- The supplied helltest was exercised using both TAR member navigation and the
  original TAR embedded-ZIP route at `[6656,7561)`. Its 905-byte ZIP SHA-256
  matches the screenshot. Its whole-file Open now returns an explicit recursion
  error without creating a file/session object. The genuine path has seven
  distinct hashes and ends at the 208-byte `basement/answer.json`, containing
  `EOX reached the basement.` Full sizes/ranges/hashes are in `HELLTEST-TRACE.md`
  and `examples/helltest-trace.json`; the source SHA-256 remained unchanged.
- Literal self-copy hash protection was exercised directly on registered objects.
  An ancestor-copy container test follows a real two-archive path, then mocks a
  corrupt/provider decoder to return the ancestor's exact bytes with the expected
  length. This is a simulated cyclic decoder result, not a claim to have built
  an ordinary finite ZIP literally containing its full own bytes.
- Mocked DOM + actual API fixture data verified a non-clickable whole-object
  record, Structure guidance, the new Provenance tab with full terminal hash and
  ancestor-return controls. JavaScript syntax and CLI budget-option checks passed.
  No real graphical browser or physical disc/provider run was used for this patch.

## Previous v0.6.3 checks

- **86 unit/integration tests passed**. New coverage includes mixed BMP/WAV/ZIP/
  PNG blobs with junk before/between/after objects, exact byte boundaries, parent
  identity versus embedded ZIP, renamed ordinary/empty ZIPs, a PNG with appended
  ZIP, multiple independent ZIPs, PNG CRC/bounds failures, RIFF chunk bounds and
  odd-byte padding, ZIP central/local mismatch and split/truncated rejection,
  validation budgets, typed carve APIs, recursive ZIP member opening and source
  preservation.
- The supplied 12,754-byte `.fekk` file passed upload → binary parent → four
  embedded objects → typed carve → exact-byte download. Pillow decoded BMP
  (37×23, offset `0x2FD`, 2,630 bytes) and PNG (19×19, `0x2C77`, 862 bytes).
  Python wave decoded the WAV (`0x1128`, 4,844 bytes) as 8 kHz mono 16-bit,
  2,400 frames. ZIP (`0x2679`, 333 bytes) passed member CRC checks; both
  `hello_from_inside.txt` and `nested/clue.txt` opened recursively. Source
  SHA-256 stayed unchanged.
- A mocked DOM check verified the parent summary, all four typed Open buttons,
  requested format/offset pairs and selection of image/audio/archive results.
  JavaScript syntax passed. No real graphical browser was used for this patch;
  native playback still depends on the target browser.

## Previous v0.6.2 checks

- **76 unit/integration tests passed**. New GB detection coverage verifies
  content-only classification with a modified logo, each required invariant,
  checksum/size warnings with canonical logos, short/zero/FF inputs, 1,000
  seeded random headers, strong parent format precedence, reserved MPEG fields,
  ROM API access, checksum repair, source preservation and embedded BMP scanning.
- The supplied 256 KiB curveball `.bin` passed upload → ROM identification →
  ROM tools API → BMP carve → download. It identifies as a GB/GBC structural
  candidate (75/100), title `EOX_CURVEBALL`, with valid header/global checksums
  and a reported logo mismatch. The 6,198-byte BMP at `0x28000` decoded as
  64×32 RGB and exactly matched its source range; source SHA-256 was unchanged.
- A mocked DOM check verifies the ROM tools tab, Overview evidence score/checks
  and logo warning. JavaScript syntax checking passed. This patch was not tested
  in a real graphical browser or against a physical cartridge.

## Previous v0.6.1 checks

- **69 unit/integration tests passed** for this patch. BMP regression coverage
  checks the reported `0x9D50` offset, top-down images, legacy core headers,
  invalid headers, truncation, bounded scanning, exact extraction with trailing
  parent data excluded, raw-slice fallback and source preservation.
- The supplied JPEG was exercised through upload → Embedded scan → Open BMP →
  download. The result exactly matched source bytes 40272–232325 inclusive
  (192,054 bytes), decoded with Pillow as a 320×200 RGB BMP, and left the source
  SHA-256 unchanged. JavaScript syntax checking passed. No real graphical
  browser was used for this patch.

## Previous v0.6 checks

- **58 unit/integration tests passed**, retaining all v0.5 checks. New coverage
  includes ZIP add/remove with source unchanged and file metadata/comment retained;
  TAR.GZ creation and ZIP repacking; unsafe archive names, duplicate names and
  provider errors; DOCX correction spanning runs with bold/italic, tables, headers
  and other package parts preserved; PDF text correction, password handling,
  width rejection, neighboring text coordinates and vector graphics retained;
  image conversion/rotation/resize with metadata removed; conversion cancellation,
  stale-source rejection, real audio conversion settings and formats, real video
  to WebM conversion and video audio extraction; archive APIs, partial-failure
  batch jobs and combined result ZIP downloads. A mocked command check covers
  explicit 900-second conversion; no 15-minute fixture was encoded.
- Real FFmpeg runs exercised WAV → MP3 → 24-bit stereo WAV at a chosen sample
  rate, FLAC, Ogg, M4A, MP4 → WebM and MP4 → WAV extraction. Optional Pillow,
  lxml, PyMuPDF and python-docx were available for fixture verification.
- Generated PDF and DOCX edited outputs were rendered and visually inspected.
  The DOCX kept its title, heading, bold/italic runs, unchanged paragraph, header
  and table. PDF rendering changed the typo and retained surrounding layout.
  PDF source Helvetica substitution has irregular spacing in this environment;
  that pre-existing rendering behavior remained unchanged by the correction.
- Mocked DOM + live backend API exercised DOCX paragraph correction, PDF clickable
  word selection/correction and result preview, new ZIP creation, archive removal,
  and full-file converter controls. JavaScript syntax checks passed. No real
  graphical browser was available; browser hit targets/playback and Windows
  launch remain target-PC checks.
- 7-Zip and the RAR writer were absent. Their adapters were not exercised against
  actual binaries. RAR/7z archive operations require those local providers.
  Scanned PDF OCR, complex PDF text reflow and PSD manipulation are not included.

## Previous v0.5 checks

- **45 unit/integration tests passed** with Python 3.12 and FFmpeg installed.
  Ten new format/API checks plus four additional streaming/imaging cases cover
  GB header/global checksum repair with untouched original, GBA checksum repair,
  NES/N64 header inspection, IPS literal/RLE/extension/truncation and malformed
  patches, generated ISO listing/extraction/equal-length replacement, source
  sector preservation, bounded verified imaging, cancellation cleanup, backup-
  only cartridge command construction, HTTP(S) URL validation, extractor header
  filtering/config isolation, direct URL byte ranges and token enforcement.
- Actual FFmpeg subprocesses fetched a local HTTP WAV source and a generated HLS
  video/audio playlist, produced fragmented MP4, and passed FFprobe checks for
  AAC audio and H.264/AAC video/audio respectively. No real third-party streaming
  site, DASH source, live infinite stream, DRM or browser media decoder was tested.
- The new controls passed mocked-DOM + live HTTP API smoke checks for ROM checksum
  repair, disc entry extraction, imaging job creation/progress and URL player/stop
  controls. JavaScript syntax checks passed. A real graphical browser is not
  available here, so actual browser rendering/playback remains unverified.
- FlashGBX, cartridge readers, optical hardware, pycdlib and yt-dlp were absent.
  FlashGBX command construction and optical-length behavior were tested using
  mocks/file fixtures. Native ISO operations need no pycdlib. Physical source
  reads, Windows device APIs and optional provider behavior require target-PC
  checks. UDF provider extraction and variable-length ISO replacement are wired
  but were not exercised against the actual optional library.

## Previous v0.4 checks

Current editing checks:

- **31 total unit/integration tests passed.** Added tests cover text/BOM/UTF-16
  preservation, untouched originals, JSON validation, quoted CSV output, byte
  bounds/stale-source rejection, ZIP-entry replacement with other contents and
  comment retained, semantic capability classification, Pillow image transforms,
  PDF page order/rotation/password handling, FFmpeg audio trimming, edit API
  tokens, parent provenance, and original/result download contents.
- Optional Pillow and pypdf were present in the test environment. Their presence
  on a user's PC is detected and shown in the capability/tool view.
- Mocked-DOM + live API smoke checks exercised JSON classification, JSON edit
  generation with unchanged original, byte-editor fields, CSV row/column addition
  and export, and PDF page range/order parsing. Graphical browser rendering
  remains unverified in this environment.
- Windows/native browser UI verification remains a target-PC check.

Previous v0.3 checks:

Current checks:

- **22 unit/integration tests passed**, including all v0.2 cases plus PCAP and
  PCAPNG byte orders/resolutions, partial capture tails, packet direction and
  tuple grouping, DNS/TLS/ARP/IPv6 layers, IP-fragment fallback, TCP sequence
  ordering/retransmission overlap/gaps/wrap, payload extraction endpoints,
  host endpoint schemas, embedded signature/slice opening, native hardware
  counters, driver-path normalization, and bounded capture command construction.
- Linux native CPU/memory/network/process providers exercised in this environment.
- JavaScript syntax passed. Mocked-DOM + real HTTP API smoke tests exercised
  packet rows, payload inspection, conversation views, drivers/process inventory,
  hardware-monitor chart calls, capture controls, and raw fallback after a rich
  decoder failure. This does not substitute for testing real browser graphics.
- Live dumpcap launch was tested with mocked processes. Wireshark/Npcap, Windows
  CIM/driver inventory, real sensor providers, actual GPU drivers and actual live
  capture were **not available here** and require verification on the target PC.

Drop `examples/demo-network.pcap` into EOX to test the packet UI without a
capture driver. Set Local IPs to `10.0.0.2` to see send/receive labels. It contains
two generated HTTP packets and no real user traffic.

Previous v0.2 checks:

Validated in Linux with Python 3.12, Node 24 and FFmpeg installed:

- 11 passing unit/integration tests: unknown and empty inputs, malformed PE,
  PE sections, RIFF chunks, native PCM samples, kernel crash headers, minidump
  exception/module correlation, OBJ/STL/ASCII PLY/GLB/embedded glTF geometry,
  JSON/CSV/UTF-16 WER, upload token and Host checks, range requests, archive
  extraction with traversal-like member names, temporary audio preview isolation.
- A real Windows x64 launcher parsed into 6 sections, 10 imported libraries and
  1 resource, without parser warnings.
- Frontend syntax checked by Node. Renderer templates and live API calls for
  overview, hex, text and strings passed a mocked-DOM smoke test, along with
  DLL/crash templates and a mocked-WebGL geometry upload/draw test.

Not verified here: graphical browser rendering, real WebGL driver behavior,
Windows launch, Windows EVTX export, PDF viewer behavior, or real customer
BSOD dump diagnosis. Crash fixtures were generated from documented layouts.
This environment had no graphical browser executable available.

The included `examples/cube.obj` provides a quick 3D check on your machine.
