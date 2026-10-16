# EOX — Every Object eXposed

Every file. Every layer.

EOX v0.6.4 is a local file workbench with basic copy editing. Every file can be opened as
bytes; rich interpretation is provided for supported formats. This is a working
prototype, not a promise that every proprietary or encrypted format can be decoded.

## Run on Windows

1. Install Python 3.10 or newer, enabling its launcher / PATH option.
2. Unzip this folder and double-click **Start-EOX.bat**.
3. Your browser opens EOX. Keep the console window open while using it.
4. For decoded waveforms, sample inspection of compressed audio, and metadata,
   install **FFmpeg** and put `ffmpeg` and `ffprobe` on PATH, then restart EOX.
   EOX does not download dependencies automatically.

On Linux / macOS: `python3 eox.py`. Optional: `--port 8765` or `--no-browser`.
No Python packages are required. All UI assets are included; no CDN is used.

## New: everyday tasks that finish the job

Use **Convert / batch / archive** in the sidebar, or a file's **Edit** tab.
Edits create new files; use **Download copy** or **Download all results as ZIP**
to retain them after closing the app. Source files are never overwritten.

### Full-file and batch conversion

Select one or multiple files (up to 200 per batch), choose output format and
click Convert. Full file is the default: start at 0 and leave duration blank.
There is no 10-minute conversion limit or overall conversion timeout. Jobs show
the current file and processed seconds, support cancellation, keep successful
results if another file fails, and offer a combined results ZIP. Only one batch
runs at a time. Closing the backend cancels active conversion processes.

- Audio: WAV, MP3, FLAC, Ogg Vorbis, M4A. Start/duration/gain, original or chosen
  sample rate, original/mono/stereo channels, 16/24/32-bit integer PCM WAV and
  MP3/M4A bitrate options. Ogg uses quality-based encoding.
- Video: MP4 (H.264/AAC) and WebM (VP9/Opus). Audio output formats extract the
  first audio track from a video. Video output uses the first video and audio
  tracks; extra tracks, chapters and subtitles are not retained. Odd MP4 image
  dimensions are padded to even dimensions for the encoder.
- Images: PNG, JPEG, WebP, BMP, TIFF. Optional rotation/resize and JPEG/WebP
  quality. Metadata is stripped, EXIF orientation is applied, and animated
  sources export their first frame. JPEG/BMP place transparent input on white.
  Pixel conversion does not preserve the original ICC profile or EXIF data.

Media conversion requires FFmpeg; image conversion requires Pillow. The older
quick audio-range exporter remains available alongside the new full-file tool.

### Archive creation and maintenance

Create ZIP, TAR or TAR.GZ archives from selected session files, or choose
**Add / remove files · repack archive** for an existing archive. Add multiple
files, tick entries to remove, and save a new archive. Remove an existing name
before adding its replacement. ZIP members retain their file metadata and the
archive comment when kept in ZIP; TAR file metadata is retained when kept in
TAR. Converting containers can change directory metadata and compression.

RAR and 7z signatures now receive container views. Install **7-Zip** for their
listing/extraction and repacking into ZIP/TAR/7z; EOX searches PATH and standard
Windows 7-Zip folders. Writing RAR requires the separate **rar** command-line
writer on PATH. Missing providers leave raw inspection available. These external
archive providers were wired but not available for real-provider testing here.

Repacking supports up to 10,000 entries, 256 MiB per file and 1 GiB expanded.
Links, special members and encrypted entries must be removed before repacking.
Relative member names must be safe and unique for staging. Signed Office/app
packages may lose their signature validity if repacked. Password-based archive
editing is not implemented.

### DOCX paragraph correction

Choose **Edit DOCX paragraphs**, find a paragraph, change its text, then generate
and download a copy. Body paragraphs, table-cell paragraphs and headers/footers
are listed. Text changes are applied across existing text runs; the rest of the
package stays byte-identical. Existing run formatting is retained; inserted text
inherits its insertion run's formatting. Special paragraphs containing fields,
hyperlinks, tracked changes, tabs/breaks or content controls remain listed but
are not edited by this basic tool. This is paragraph editing, not a page-layout
editor. Requires lxml. Try `examples/paragraph-typo.docx`.

### Click-to-correct PDF text

Choose **Correct PDF text**, load a page, click a word, correct it, then generate
a copy. The saved PDF is previewed before download. Enter a supplied password
when needed. The selected text is actually removed, then the replacement is
inserted at its baseline; images, vector graphics and neighboring text remain.
The source font is reused when available with the replacement glyphs; a standard
font is used otherwise. Small width differences can fit with up to 20% size
reduction. Longer replacements that cannot fit are rejected instead of silently
covering adjacent text. Document text extraction order can change after replacement.

This tool covers short corrections in horizontal, selectable PDF text. It does
not reflow paragraphs, implement scanned-page OCR, or guarantee exact matching
for every embedded/subset font. Pending-redaction pages must be handled separately.
Output is unencrypted and existing digital signatures are not preserved. Requires
PyMuPDF. Try `examples/typo.pdf` and correct “recieve” to “receive”.

## URL audio / video streaming

Choose **URL audio / video** in the sidebar. Paste an HTTP(S) URL and select
Auto, Direct media URL, or Resolve website page. EOX forwards media byte ranges
for direct playback, without loading the site's webpage player. Optional **yt-dlp**
resolves public website pages to a media URL. Its configuration is ignored;
EOX does not import cookies, browser logins or downloader hooks.

**FFmpeg playback** outputs H.264/AAC fragmented MP4 for browser playback,
including HLS and basic DASH inputs. Transcoding starts at the beginning and
cannot seek; direct playback can seek when the source supports range requests.
Stop stream ends the player and its transcoder. Two simultaneous transcoders
are permitted. A network input has a 15-second FFmpeg I/O timeout.

Website resolution prefers a combined video/audio format, then audio-only,
then a single available format. It does not merge separately served tracks,
implement an authenticated browser session, or handle DRM/license playback.
External sources are contacted only after you submit a URL. Removing the
webpage player avoids its display ads; ads already stitched into the actual
media remain. EOX cannot guarantee an ad-free stream.

Install **FFmpeg** on PATH for transcoding, and optional **yt-dlp** with the
requirements file for website URL extraction. Basic direct URLs need neither
Python provider; original playback depends on browser codecs. File metadata,
files and host metrics stay local; streaming contacts the chosen external source.

## ROMs, disc images and source dumping

GB/GBC identification now uses content at the fixed cartridge-header location,
independent of the filename. Its evidence score combines Nintendo logo (25),
header checksum (25), declared size versus actual file length (20), plausible
cartridge fields (10), readable title (10), and conventional entry jump (10).
A noncanonical logo requires every other check to pass (75/100); a canonical
logo retains recognition of damaged dumps and reports checksum/size mismatches.
The score is a heuristic, not a probability. The Overview and ROM tools show
these checks. Structural GB evidence wins over weak MPEG frame signatures;
reserved MPEG header fields such as `FF FF FF FF` no longer identify audio.
Known strong parent signatures still win over a noncanonical GB candidate.
Nonstandard homebrew entry/header layouts can remain raw candidates; GBA, DS
and SNES filename-based identification is unchanged in this patch.

The **ROM tools** tab provides platform headers, classic IPS patch application,
and GB/GBC/GBA checksum repair. The ordinary **Edit** tab can also replace a
byte range. All changes create new copies. ROM headers cover GB/GBC, GBA,
iNES/NES 2.0, Nintendo DS, N64 byte orders and SNES header candidates. Other
ROM formats retain byte/text inspection and IPS/byte patching. A recognized
header or valid checksum does not prove that a cartridge's full bank set was
read or that an emulator implements its mapper.

The **Disc tools** tab lists native ISO9660/Joliet filesystem entries, extracts
files (up to 64 MiB), and replaces a single-extent file in a new image.
Native replacement requires the exact original byte length and preserves
other sectors. Optional **pycdlib** enables UDF filesystem inspection/extraction
and ISO replacement within an existing file's allocated extent; it does not
provide unrestricted growth, adding/removing entries or arbitrary rebuilding.
Replacement uploads are limited to 64 MiB. Multi-extent, interleaved and extended-
attribute entries retain raw inspection instead of native extraction/replacement.

ISO/UDF/IMG/CUE/CHD/CSO/MDF/NRG candidates can always be opened as bytes.
Format-specific decoders for CHD/CSO/MDF/NRG or audio/mixed-mode track layouts
are not included. A raw `.bin` is classified by content, rather than assumed to
be a disc merely because of its extension. Boot data and disc/container metadata
are not regenerated by raw editing. Blu-ray/DVD encrypted content stays encoded;
there is no decryption, license handling, disc burning or cartridge flashing.

**ROM / disc imaging** creates a new session file through one of these routes:

- **File / mounted reader ROM:** clone an existing file, including one exposed
  by a mounted cartridge adapter. A second source read checks SHA-256; the
  generated destination is hashed and compared with the copied bytes as well.
- **Optical data disc → ISO:** select an enumerated optical drive. Read its
  logical data sectors until its OS-reported length or EOF, with optional
  second-read verification. OS read permissions still apply. Damaged/read-error
  media fails with a note rather than silently zero-filling. This route is
  intended for single-session data discs; audio, multisession, subchannel data,
  copy-protection characteristics and exact physical-disc duplication need
  dedicated readers/formats. Windows/Linux drive paths are enumerated; macOS
  physical-drive enumeration is not implemented.
- **FlashGBX cartridge → ROM:** install FlashGBX separately and connect one of
  its compatible readers. This adapter covers **GB/GBC and GBA** and invokes
  only its `backup-rom` action. It checks the installed CLI help before running,
  optionally selects an enumerated serial port, and imports the completed dump.
  Reader prompts, reader support and cartridge mapper support remain provider
  requirements. FlashGBX's reader output is not labelled second-read verified
  by EOX. Other systems can import a dump made with their appropriate reader.

Clone the currently open ROM/disc directly from its tools tab, or enter a full
local source path in the imaging sidebar. Jobs show progress, support cancellation,
and delete partial outputs after cancellation/failure. One imaging job runs at a
time. Closing EOX clears temporary outputs; **Download dump** to keep your result.
File sources are checked for sufficient free space before copying; optical
capacity is checked when exposed by the driver. Total session disk usage is not
capped. FlashGBX and physical optical drives need a target-PC verification;
only file copies and constrained provider command construction were tested here.

Primary provider references:
[yt-dlp](https://github.com/yt-dlp/yt-dlp),
[FlashGBX](https://github.com/lesserkuma/FlashGBX),
[pycdlib](https://clalancette.github.io/pycdlib/).

## Identification and appropriate editing tools

Each file's Overview explains **what EOX opened**, its identification evidence,
semantic type versus extension, readable layers, relevant tools, and provider
availability. ZIP-based Word/Excel/PowerPoint packages are distinguished from
generic archives; Windows `.sys` drivers, DLLs and PE executables are labelled.
Identification is still heuristic and parser notes remain visible.

The **Edit** tab offers operations appropriate to the detected file. Generate an
edited copy, inspect it in EOX, then **Download edited copy** to keep it. Editing
never overwrites the original path. Browser downloads may be renamed by your
browser. Drafts stay in browser memory; Reset draft discards them. Undo across
generated copies means reopening the earlier copy in Session Files.

- Text: full-file editing up to 4 MiB, strict UTF-8 or BOM-marked UTF-16 decoding,
  preserving encoding/BOM. Browser text edits restore original CRLF style.
- JSON: validation, formatting and minification. Invalid JSON is rejected for
  structured export; the plain text tool remains available for deliberate edits.
- CSV/TSV: editable cells, row add/delete and column add; selectable comma, tab,
  semicolon or pipe export. Maximum 2,000 rows / 100 columns. Quoting and ragged
  row formatting can change; CSV values are exported as text.
- All files: hexadecimal byte replacement at a chosen offset, 1 byte to 1 MiB
  per patch, preserving file length. Large files stream into a new copy. Source
  hash checks reject changed inputs. The byte editor does not repair checksums/signatures; the separate ROM tools can repair GB/GBC/GBA checksums.
- Images with Pillow: crop rectangle, clockwise 90-degree rotations and resize;
  export as PNG. First frame only, no preservation of original animation/metadata.
- Audio with FFmpeg: start/duration/gain controls, decoded PCM16 WAV export,
  up to 600 seconds. Video input can export its audio; no video timeline editor.
- ZIP: replace one unencrypted UTF text entry while retaining other member
  contents, names, metadata and archive comment. 64 MiB input / member size cap,
  128 MiB expanded archive cap, 10,000 entries. Text entries up to 4 MiB.
  Repacking can invalidate signed package signatures; no Office WYSIWYG editing.
- PDFs with pypdf: supplied-password opening, page count, select/extract/reorder
  using one-based pages (e.g. `3,1,2` or `1-5`), clockwise rotation and PDF export.
  Output is unencrypted. The separate PDF text tool handles short corrections. Page content text is not reflowed; document-level forms,
  links, metadata and signatures are not guaranteed to survive page extraction.
- OBJ/glTF text source: weak source editing plus subsequent normal inspection.
  No 3D sculpting or format-aware executable code editor.

Install the optional PDF/image/host providers:
`python -m pip install -r requirements-optional.txt`

Structured editing uses at most 64 MiB input files; text has the lower limit
above. Provider limits are shown instead of rejecting file inspection. Some
malformed or unrecognized files may offer only byte editing. Passwords entered
for PDF tools are held in browser draft memory until Reset draft or session close;
they are not written to files or server logs. Editing should be performed while
the directly opened source remains unchanged on disk.

## New: PC network and hardware views

Use the sidebar's **Network packets**, **Hardware monitor**, **Hardware
inventory**, **Drivers**, and **Processes / EXEs** views. The Connections tab
shows current socket endpoints and process IDs where the OS exposes them.

- For live capture on Windows, install Wireshark with Npcap. EOX finds dumpcap
  and TShark on PATH or in the standard Wireshark installation folder. The
  selected adapter must permit capture; Npcap's administrator-only installation
  option may require starting EOX as administrator. EOX never elevates itself.
  On Linux/macOS, install Wireshark/dumpcap and configure its normal capture
  permissions. Saved PCAP/PCAPNG files need no capture driver.
- Start capture explicitly, select adapter/duration, optionally enter a BPF
  capture filter, then click Start. Stop is always available. Each capture stops
  after the requested duration (maximum 600 seconds), 128 MB or 20,000 packets.
  Promiscuous mode is disabled. Capture continues if you change tabs until
  stopped or its limit is reached. Closing the backend stops capture.
- Packet rows show direction, endpoints, protocol, wire length and readable
  summaries. Filter rows, follow endpoint conversations, inspect headers and
  payload hex/text, download payloads, or open payloads/contiguous segments as
  ordinary EOX files. Download the full PCAPNG or conversation JSON to keep it.
- PCAP endian variants and microsecond/nanosecond timestamps, plus PCAPNG
  section/interface/enhanced/old/simple packet blocks are parsed natively.
  Partial tails are tolerated while recording. The listing is capped at 20,000
  records. Link types include Ethernet/VLAN, raw IP, null/loopback and Linux
  cooked v1/v2. Other link types retain raw bytes.
- Native layers include IPv4/IPv6, TCP/UDP, ICMP, ARP, DNS, HTTP header text and
  TLS record metadata. TShark supplies additional dissectors on request.
  Checksums are displayed where parsed, not validated. DNS/HTTP/TLS recognition
  is packet-local; headers split across packets may need conversation inspection
  or TShark. This is not Wireshark feature parity.
- Send/receive mapping uses host IP addresses; edit **Local IPs** when opening
  a capture made on another machine. Peer traffic is labelled separately.
  Conversation rows aggregate endpoint tuples rather than distinct TCP sessions.
  Sequence-aware payload stitching handles order, retransmission overlap and
  common 32-bit wrap cases. Gaps remain separate; each direction is capped at
  1 MiB. IP fragments are not reassembled. Captured data may be truncated.
  TLS ciphertext, compression, and application-specific encoding remain encoded;
  EOX does not recover keys or promise reconstruction of transmitted files.
- CPU/memory/disk/network counters work through native Windows APIs or Linux
  proc/sysfs, with optional psutil enrichment. Install richer host metrics with
  `python -m pip install -r requirements-optional.txt`.
- NVIDIA GPU metrics use nvidia-smi. For Windows board/CPU sensors, run
  LibreHardwareMonitor with its WMI provider enabled. Missing sensor readings
  appear as provider notes. EOX never invents temperatures or fan speeds.
- Windows hardware/driver/process inventories use bundled, read-only PowerShell
  CIM queries. Driver `.sys` and process `.exe` paths have **Open** buttons;
  the file then opens through EOX's normal PE/bytes views. OS access controls
  still apply. EOX does not unload drivers, modify hardware or execute binaries.

## Fallback behavior

Every file keeps its hex/text/strings views regardless of its extension. When a
rich decoder cannot produce a view, EOX shows the available raw layers and the
reason rather than a rejection badge. Readable content is not guaranteed for
encrypted, damaged or undocumented data. **Embedded** scans the first 64 MiB
for known byte signatures. Unknown binary parents show an **Embedded objects**
summary in Overview; a ZIP elsewhere in the bytes does not turn the whole parent
into an archive. ZIP primary identity requires its first local header (or empty
archive directory) at offset zero. SFX executables retain executable inspection
with their ZIP accessible through Embedded.

**Embedded** offers exact-range opening for these structurally checked objects:

- BMP: plausible file/DIB headers, dimensions, declared size and truncation status.
- WAV, WebP and AVI: RIFF declared length and top-level chunk bounds; WAV requires
  `fmt ` and `data` chunks when the complete payload is in the scan window.
- PNG: IHDR dimensions/layout, chunk bounds and CRCs through IEND.
- Classic ZIP: single-disk central directory, matching local records and EOCD plus
  archive comment. Each archive appears once rather than one row per local entry.
  Carved archives open normally and expose their member files recursively.

Opening rechecks the boundary, extracts only that range, preserves the appropriate
extension and opens a new session file. Carve provenance records the parent ID,
offset, length and boundary evidence. Originals remain unchanged. Raw byte opening
remains available for signatures without a known boundary. Truncated declared-size
BMP/RIFF objects are marked; incomplete or corrupt PNG/ZIP structures remain weaker
signature candidates. Header/chunk checks do not guarantee payload decoding.

The scan reads at most 64 MiB, returns at most 512 candidates, checks at most
65,536 BMP signature hits and uses a 128 MiB cumulative structural-validation byte
budget. Exact extraction is limited to 64 MiB. ZIP64, split ZIPs, unusual ZIP
layouts, objects crossing the scan window, nested RIFF interpretation and exact
boundaries for other signature types are outside this patch's structural readers.
Those files still retain raw inspection.

## Navigation identity and recursion protection

Embedded scanning separates whole-object identity from genuine child ranges.
A checked candidate beginning at zero and spanning the current file appears as
an identity note, with no Open button. Truncated candidates and ancestry cycles
appear as blocked records. Unknown-length top-level signatures are inspection
notes; raw whole-file reopening is also refused by the backend. A shorter valid
prefix object at zero remains openable when other data follows it.

Every opened root, embedded slice and archive/disc member carries provenance:
parent ID, relation, source coordinate system, absolute start/end/length, and
SHA-256. Embedded slices retain their source coordinates. Decoded members get
new coordinates; ZIP compressed storage ranges and uncompressed TAR/ISO member
ranges are recorded separately. Compressed TAR member offsets are identified as
positions in its decoded stream, not physical source offsets. Provider-only
RAR/7z ranges are explicitly unavailable.

The **Provenance** tab shows the full chain, sizes, hashes, ranges and resource
usage, and offers Return here for earlier objects. A child with the current or
an ancestor's exact source range, or the same length and SHA-256 content, is
refused. Rejection creates no session child and rolls back temporary output and
resource reservation. Checks apply to ancestry, not a global hash blacklist:
identical payloads at independent sibling locations still open normally.

There is **no fixed nesting-depth cap**. Secondary resource controls reserve
space before decoding: at most 64 MiB per navigated child, default 512 MiB total
materialized navigation bytes and 10,000 successful children per backend session.
ZIP/TAR decoded lengths must match metadata; stream copying stops if actual
output exceeds its declared length or the per-child limit. ZIP member records
must remain outside the central directory; TAR links are listed, not followed.
Existing objects retain inspection when a resource budget is reached.

For a larger deliberate session, run e.g.:
`python3 eox.py --navigation-budget-mib 2048 --navigation-max-objects 20000`.
The scan has its existing byte/candidate/checking caps and a separate 128 MiB
scan-time ancestry-hash budget. Open-time ancestry checks still run if that hash
budget is exhausted. These limits cover container/embedded navigation; media
conversion and other jobs retain their own documented limits. Direct sources
must still match their opened SHA-256 before navigating.

`examples/recursive-helltest.fukk` is the frozen regression fixture.
`HELLTEST-TRACE.md` and `examples/helltest-trace.json` record the real seven-object
path to `basement/answer.json`, including full hashes and physical/decoded ranges.

## What works

- 3D: interactive WebGL solid/wireframe rotation and zoom for OBJ, binary/ASCII
  STL, ASCII PLY, GLB 2 and embedded-buffer glTF. Point-only meshes render as points.
  Preview parsing is capped at 64 MiB, 450,000 vertices and 150,000 triangles.
  glTF renders mesh-local positions: no node transforms, animation, textures,
  skins, sparse accessors or Draco. External-buffer glTF requires conversion
  to a self-contained GLB. FBX/BLEND/STEP/IGES/USD/DAE/3DS are recognized by
  extension and receive raw/text inspection rather than geometry rendering.
- Windows BSOD / crash files: PAGE/DUMP and PAGE/DU64 kernel dump headers expose
  stop code, common stop-code name, parameters, version and CPU count. MDMP dumps
  expose stream directory, system information, modules, thread records and
  exception facts where available. Module/address matching is not root-cause
  diagnosis. No automatic symbol downloads or WinDbg stack analysis.
- Windows EVTX: readable event XML through built-in `wevtutil` on Windows,
  first 2,000 events. Other systems retain hex/strings access.
- JSON gets an indented view; CSV/TSV gets a table; WER and key=value logs get
  extracted fields and labelled bugcheck candidates. Structured text parsing
  is capped at 4 MiB. BOM-marked UTF-16 WER and text files are supported.

- All file types: paged hex, ASCII column, UTF-8 text, readable strings with
  offsets, SHA-256 and a first-64-KiB entropy estimate. Empty files work too.
- MP3, WAV, FLAC, Ogg: original browser playback when the browser supports the
  codec; FFmpeg decoded playback, clickable waveform, and sample-frame table.
- PCM16 WAV: sample table reads exact native samples, at native rate and channel
  count. Other audio uses a clearly labelled stereo PCM16 decode preview.
- RIFF/WAV: chunk listing and format metadata.
- ZIP-based formats including DOCX/XLSX/PPTX/JAR/APK: container entries can be
  opened recursively, including nested archives. This is container inspection,
  DOCX paragraph editing is provided separately; other Office document rendering/editing is not included.
- TAR, including gzip/bzip2/xz compressed TAR: listing and regular-entry opening.
- Windows PE DLL/EXE: headers, sections, imported libraries and symbols,
  named and ordinal exports, forwarded exports, resource leaf listing, and
  jumps to section/resource bytes. Code is never loaded or executed.
- PNG/JPEG/GIF/BMP/WebP: browser image preview. PDF: browser PDF viewer.
- MP4/ISO media and Matroska/WebM: signature detection and browser video
  playback when supported; audio preview through FFmpeg. Local-file video transcoding is not included; URL streams have FFmpeg playback.
- ELF: recognized and available through raw inspection.

## Limits and behavior

- Drag/drop uploads support up to 2 GiB per open. For larger files, use **Open
  local path** and paste an absolute filename; this reads the original directly
  without copying and has no app-imposed size cap. SHA-256 scans the full file,
  so opening large dumps takes time. A directly opened file should remain
  unchanged on disk during inspection. Files selected through upload are
  streamed into a temporary session copy;
  originals are untouched. Restarting clears session files. Total session disk
  usage is not capped; close/restart EOX to clear accumulated copies.
- Compressed audio waveform/decode preview covers the first 300 seconds and is
  resampled to 22,050 Hz stereo PCM16. It is not an original encoded-frame view.
  Original browser playback still exposes the full file.
- Text view displays the first 1 MiB. String scan covers the first 16 MiB,
  capped at 5,000 results; it recognizes ASCII and ASCII-range UTF-16LE strings.
- Container listings are capped at 10,000 entries. Entry decompression is capped
  at 64 MiB. Encrypted ZIPs, TAR links and special members are listed only.
- RAR/7z, uncommon image formats, encrypted files, unknown formats and unsupported
  media codecs fall back to bytes. Unknown extensions are not rejected.
- Identification uses content signatures. Some signatures are ambiguous;
  successful detection does not guarantee successful decoding.
- PE tables are bounded; malformed or unsupported structures report parser notes
  and still leave raw bytes accessible. This is not a full disassembler.
- EOX listens only on 127.0.0.1 with a random port by default. Host validation
  and session tokens protect uploads against unrelated web origins.
- HTML and scripts are shown as text, never rendered as executable documents.
  External file references in media are restricted by FFmpeg's protocol whitelist.
  This prototype is not a hardened forensic sandbox for hostile input files.

## Development

`python3 -m unittest discover -s tests -v`

The core format detection is in `inspect`; the PE and RIFF parsers are independent
functions. The HTTP interface supplies bounded byte pages and lazy audio decoding.
New parsers can be added without changing the universal raw fallback.

PE layout reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
