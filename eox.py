#!/usr/bin/env python3
"""EOX: local, read-only file explorer. Python 3.10+, no Python dependencies."""
import argparse
import hashlib
import json
import math
import mimetypes
import mmap
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import tarfile
import tempfile
import threading
import wave
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote, quote
from formats import crash_structure, mesh_data, structured_text
import hardware
import network
import editing
import discrom
import streaming
import imaging
import everyday
import embedded
import navigation

ROOT = Path(__file__).parent
LIMIT = 2 * 1024**3
EXTRACT_LIMIT = 64 * 1024**2
TOKEN = secrets.token_urlsafe(32)
WORK = tempfile.TemporaryDirectory(prefix='eox-')
FILES = {}
LOCK = threading.Lock()
NAVIGATION_BUDGET = navigation.NavigationBudget()
CAPTURES = network.CaptureManager(WORK.name)
STREAMS = streaming.URLStreams()


def pe_structure(b):
    """Read PE headers, sections, imports, exports and resource leaves; never load code."""
    def unpack(fmt, off):
        if off < 0 or off + struct.calcsize(fmt) > len(b):
            raise ValueError('PE structure points outside file')
        return struct.unpack_from(fmt, b, off)
    def cstr(off):
        if not 0 <= off < len(b):
            return '<invalid offset>'
        end = b.find(b'\0', off, min(len(b), off + 512))
        return bytes(b[off:end if end >= 0 else min(len(b), off + 512)]).decode('utf-8', 'replace')
    p = unpack('<I', 0x3c)[0]
    if b[p:p+4] != b'PE\0\0':
        raise ValueError('DOS header present, but no PE signature')
    machine, count, stamp, _, _, optsize, flags = unpack('<HHIIIHH', p+4)
    if count > 96:
        raise ValueError('Unreasonable PE section count')
    opt = p + 24
    magic = unpack('<H', opt)[0]
    if magic not in (0x10b, 0x20b):
        raise ValueError('PE header variant requires an additional parser; raw bytes available')
    directories = opt + (112 if magic == 0x20b else 96)
    sections = []
    for i in range(count):
        off = opt + optsize + i*40
        name, virtualsize, rva, size, raw, _, _, _, _, characteristics = unpack('<8sIIIIIIHHI', off)
        if raw + size > len(b):
            raise ValueError('Truncated PE section')
        sections.append(dict(name=name.rstrip(b'\0').decode('ascii', 'replace'), offset=raw,
                             size=size, rva=rva, virtual_size=virtualsize, flags=hex(characteristics)))
    def rvaoff(rva):
        for s in sections:
            delta = rva-s['rva']
            if 0 <= delta < s['size']:
                return s['offset'] + delta
        if 0 <= rva < unpack('<I', opt+60)[0] and rva < len(b):
            return rva
        raise ValueError('Unmapped PE RVA')
    dircount = unpack('<I', opt+(108 if magic == 0x20b else 92))[0]
    def directory(i):
        if i >= dircount or directories+8*(i+1) > opt+optsize:
            return (0, 0)
        return unpack('<II', directories+i*8)
    imports, exports, resources, warnings = [], [], [], []
    try:
        rva, size = directory(1)
        if rva and size:
            start = rvaoff(rva)
            for i in range(min(size//20, 4096)):
                thunk, _, _, name, first = unpack('<IIIII', start+i*20)
                if not (thunk or name or first):
                    break
                entry = dict(library=cstr(rvaoff(name)), symbols=[])
                t = rvaoff(thunk or first)
                width = 8 if magic == 0x20b else 4
                for j in range(8192):
                    value = unpack('<Q' if width == 8 else '<I', t+j*width)[0]
                    if not value:
                        break
                    entry['symbols'].append('ordinal '+str(value & 65535) if value >> (width*8-1)
                                            else cstr(rvaoff(value)+2))
                imports.append(entry)
    except (ValueError, struct.error) as e:
        warnings.append('Imports: '+str(e))
    try:
        rva, size = directory(0)
        if rva and size:
            d = rvaoff(rva)
            _, _, _, _, _, base, nfunc, nnames, funcs, names, ordinals = unpack('<IIHHIIIIIII', d)
            named = {}
            for i in range(min(nnames, 16384)):
                nrva = unpack('<I', rvaoff(names)+i*4)[0]
                ordinal = unpack('<H', rvaoff(ordinals)+i*2)[0]
                named[ordinal] = cstr(rvaoff(nrva))
            for i in range(min(nfunc, 16384)):
                addr = unpack('<I', rvaoff(funcs)+i*4)[0]
                if addr:
                    exports.append(dict(name=named.get(i, ''), ordinal=base+i, rva=hex(addr),
                                        forwarder=cstr(rvaoff(addr)) if rva <= addr < rva+size else ''))
    except (ValueError, struct.error) as e:
        warnings.append('Exports: '+str(e))
    try:
        rva, size = directory(2)
        if rva and size:
            rs = rvaoff(rva)
            seen = set()
            def walk(rel, parts, depth=0):
                if depth > 8 or rel in seen or len(resources) >= 4096:
                    return
                seen.add(rel)
                if rel+16 > size:
                    raise ValueError('Resource directory outside resource region')
                named, ids = unpack('<HH', rs+rel+12)
                for i in range(min(named+ids, 4096)):
                    pos = rel+16+i*8
                    if pos+8 > size:
                        raise ValueError('Resource entry outside resource region')
                    name, child = unpack('<II', rs+pos)
                    label = str(name)
                    if name & 0x80000000:
                        no = name & 0x7fffffff
                        n = unpack('<H', rs+no)[0]
                        if no+2+n*2 > size:
                            raise ValueError('Resource name outside region')
                        label = bytes(b[rs+no+2:rs+no+2+n*2]).decode('utf-16le', 'replace')
                    path = parts+[label]
                    if child & 0x80000000:
                        walk(child & 0x7fffffff, path, depth+1)
                    else:
                        if child+16 > size:
                            raise ValueError('Resource data entry outside region')
                        drva, length, codepage, _ = unpack('<IIII', rs+child)
                        offset = rvaoff(drva)
                        if offset+length > len(b):
                            raise ValueError('Resource data outside file')
                        resources.append(dict(name='/'.join(path), offset=offset, size=length, codepage=codepage))
            walk(0, [])
    except (ValueError, struct.error) as e:
        warnings.append('Resources: '+str(e))
    return dict(format='PE32+' if magic == 0x20b else 'PE32', machine=hex(machine),
                timestamp=stamp, characteristics=hex(flags), sections=sections,
                imports=imports, exports=exports, resources=resources, warnings=warnings)


def riff_structure(b):
    chunks = []
    end = min(len(b), struct.unpack_from('<I', b, 4)[0]+8)
    off = 12
    while off+8 <= end and len(chunks) < 10000:
        name = bytes(b[off:off+4]).decode('ascii', 'replace')
        size = struct.unpack_from('<I', b, off+4)[0]
        if off+8+size > end:
            chunks.append(dict(name=name, offset=off+8, size=max(0, end-off-8), truncated=True))
            break
        chunk = dict(name=name, offset=off+8, size=size)
        if name == 'fmt ' and size >= 16:
            fmt, channels, rate, byte_rate, align, bits = struct.unpack_from('<HHIIHH', b, off+8)
            chunk['audio'] = dict(encoding=fmt, channels=channels, sample_rate=rate,
                                 byte_rate=byte_rate, block_align=align, bits_per_sample=bits)
        chunks.append(chunk)
        off += 8+size+(size & 1)
    return chunks


def inspect(path, name):
    size = path.stat().st_size
    result = dict(name=name, size=size, kind='binary', format='Unknown / raw bytes', warnings=[],
                  ffmpeg=bool(shutil.which('ffmpeg')), ffprobe=bool(shutil.which('ffprobe')))
    sha = hashlib.sha256()
    with path.open('rb') as f:
        while block := f.read(1024*1024):
            sha.update(block)
    result['sha256'] = sha.hexdigest()
    if not size:
        result.update(kind='text', format='Empty file')
        return result
    with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as b:
        head = b[:65536]
        hist = [0]*256
        for v in head:
            hist[v] += 1
        rom_detection=discrom.gb_detection(head,size)
        result['entropy'] = round(-sum((n/len(head))*math.log2(n/len(head)) for n in hist if n), 3)
        try:
            if head[:4] in network.PCAP_MAGIC or head[:4] == b'\x0a\x0d\x0d\x0a':
                result.update(kind='packets', format='Network capture / PCAPNG' if head[:4] == b'\x0a\x0d\x0d\x0a' else 'Network capture / PCAP')
            elif head[:4] == b'MDMP' or head[:8] in (b'PAGEDU64', b'PAGEDUMP'):
                result.update(kind='crash', format='Windows crash dump', crash=crash_structure(b))
            elif head[:8] == b'ElfFile\0':
                result.update(kind='eventlog', format='Windows Event Log (EVTX)')
            elif head[:4] == b'NES\x1a' or head[0x104:0x134]==discrom.GB_LOGO or head[:4] in (b'\x80\x37\x12\x40',b'\x37\x80\x40\x12',b'\x40\x12\x37\x80'):
                result.update(kind='rom',format='Cartridge / ROM image')
                if rom_detection and rom_detection['accepted']:
                    result['rom_detection']=rom_detection
                    result['warnings'].extend(rom_detection['warnings'])
            elif head[32769:32774] == b'CD001' or any(head[n*2048+1:n*2048+6] in (b'NSR02',b'NSR03') for n in range(16,32)):
                result.update(kind='disc',format='Disc image / '+Path(name).suffix.lstrip('.').upper())
            elif head[:4] == b'glTF':
                result.update(kind='model',format='3D model / GLB',model_supported=True)
            elif name.lower().rsplit('.',1)[-1] in ('obj','stl','ply','glb','gltf','fbx','3ds','blend','dae','usd','usda','usdc','usdz','step','stp','iges','igs') and not embedded.primary_zip(path):
                result.update(kind='model', format='3D model / '+name.rsplit('.',1)[-1].upper())
                result['model_supported'] = name.lower().rsplit('.',1)[-1] in ('obj','stl','ply','glb','gltf')
            elif embedded.primary_zip(path):
                with zipfile.ZipFile(path) as z:
                    members = z.infolist()
                    result.update(kind='archive', format='ZIP container', entries=[dict(index=i,
                        name=e.filename, size=e.file_size, compressed=e.compress_size, directory=e.is_dir(),
                        encrypted=bool(e.flag_bits & 1)) for i, e in enumerate(members[:10000])])
                    if len(members) > 10000:
                        result['warnings'].append('Entry listing capped at 10,000')
            elif head.startswith(b'Rar!\x1a\x07') or head[:6]==b'7z\xbc\xaf\x27\x1c':
                result.update(kind='archive',format='RAR container' if head.startswith(b'Rar!') else '7z container',entries=[])
                result['entries']=everyday.external_entries(path)
            elif head[:2] == b'MZ':
                result.update(kind='pe', format='Windows executable / library / driver', pe=pe_structure(b))
            elif head[:4] == b'RIFF' and head[8:12] == b'WAVE':
                result.update(kind='audio', format='WAVE / RIFF', chunks=riff_structure(b))
            elif head[:2] in (b'\xff\xfe',b'\xfe\xff'):
                result.update(kind='text', format='UTF-16 text')
            elif head[:4] in (b'fLaC', b'OggS'):
                result.update(kind='audio', format='FLAC' if head[:4] == b'fLaC' else 'Ogg container')
            elif head[:8] == b'\x89PNG\r\n\x1a\n' or head[:3] == b'\xff\xd8\xff' or head[:6] in (b'GIF87a', b'GIF89a') or head[:2] == b'BM' or (head[:4] == b'RIFF' and head[8:12] == b'WEBP'):
                result.update(kind='image', format='Raster image')
            elif head[:5] == b'%PDF-':
                result.update(kind='pdf', format='PDF document')
            elif head[4:8] == b'ftyp' or head[:4] == b'\x1aE\xdf\xa3':
                result.update(kind='video', format='ISO media' if head[4:8] == b'ftyp' else 'Matroska / WebM')
            elif head[:4] == b'\x7fELF':
                result['format'] = 'ELF executable / shared object (raw inspection)'
            elif rom_detection and rom_detection['accepted']:
                result.update(kind='rom',format='Game Boy / Game Boy Color (structural candidate)',rom_detection=rom_detection)
                result['warnings'].extend(rom_detection['warnings'])
            elif head[:3] == b'ID3' or discrom.mpeg_frame_header(head):
                result.update(kind='audio', format='MPEG audio (signature candidate)')
            elif tarfile.is_tarfile(path):
                with tarfile.open(path) as t:
                    entries = []
                    for i, e in enumerate(t):
                        if i >= 10000:
                            result['warnings'].append('Entry listing capped at 10,000')
                            break
                        entries.append(dict(index=i, name=e.name, size=e.size, directory=e.isdir(),
                                            regular=e.isfile(), type=e.type.decode('ascii', 'replace')))
                    result.update(kind='archive', format='TAR container', entries=entries)
            elif Path(name).suffix.lower() in discrom.ROM_EXTS:
                result.update(kind='rom',format='Cartridge / ROM image (extension candidate)')
            elif Path(name).suffix.lower() in discrom.DISC_EXTS- {'.bin'}:
                result.update(kind='disc',format='Disc image / track container (extension candidate)')
            else:
                try:
                    # Ignore incomplete trailing codepoint in the bounded sniff window.
                    import codecs
                    sample = codecs.getincrementaldecoder('utf-8')().decode(head, final=size<=len(head))
                    if '\0' not in sample and sum(ord(c)<32 and c not in '\n\r\t' for c in sample) <= len(sample)*.01:
                        result.update(kind='text', format='UTF-8 text')
                except UnicodeError:
                    pass
        except (ValueError, OSError, struct.error, zipfile.BadZipFile, tarfile.TarError, subprocess.TimeoutExpired) as e:
            result['warnings'].append('Structure parser: '+str(e))
    if result['kind']=='binary' and result['format']=='Unknown / raw bytes':
        discovery=embedded.scan(path)
        result['embedded_objects']=discovery['candidates']
        result['embedded_scan']=dict(scanned=discovery['scanned'],limited=discovery['limited'],note=discovery['note'])
    if result['kind'] == 'text' and size <= 4*1024**2:
        structured=structured_text(path.read_bytes(), name)
        if structured:
            result['structured']=structured
    if result['ffprobe'] and result['kind'] in ('audio', 'video'):
        try:
            run = subprocess.run(['ffprobe', '-v', 'error', '-protocol_whitelist', 'file,pipe',
                                  '-show_format', '-show_streams', '-of', 'json', str(path)],
                                 capture_output=True, timeout=20)
            if run.returncode == 0:
                result['media'] = json.loads(run.stdout)
            else:
                result['warnings'].append('Media probe could not decode this file')
        except (subprocess.TimeoutExpired, ValueError) as e:
            result['warnings'].append('Media probe: '+str(e))
    return result


def register(path, name, parent_id=None, origin=None):
    ident = secrets.token_urlsafe(18)
    data = inspect(path, name)
    if parent_id:
        data['provenance']=navigation.child_provenance(FILES,ident,parent_id,data['size'],data['sha256'],origin)
    else:data['provenance']=navigation.root_provenance(ident,data['size'])
    data['profile']=editing.capabilities(path,data)
    with LOCK:
        FILES[ident] = dict(path=path, data=data, audio_lock=threading.Lock())
    return dict(id=ident, **data)


def resolve_additions(items):
    if not isinstance(items,list) or len(items)>200:raise ValueError('Choose at most 200 added files')
    result=[]
    for entry in items:
        item=FILES.get(entry.get('id'))
        if not item:raise ValueError('Added file session not found')
        everyday.source_check(item['path'],item['data'])
        result.append(dict(path=str(item['path']),name=entry.get('name') or item['data']['name']))
    return result

IMAGING = imaging.ImagingJobs(WORK.name,register)
TASKS = everyday.TaskJobs(WORK.name,register)

def packet_source(q):
    if q.get('capture'):
        path=CAPTURES.path(q['capture'])
        if not path.exists():return path,None
        owner=CAPTURES.sessions[q['capture']]
    else:
        owner=FILES.get(q.get('id'))
        if not owner:raise ValueError('File session not found')
        path=owner['path']
    addresses=[a.strip() for a in q['local_ips'].split(',') if a.strip()] if 'local_ips' in q else network.local_addresses()
    # Validate addresses rather than treating labels as local peers.
    import ipaddress
    addresses=[str(ipaddress.ip_address(a)) for a in addresses[:64]]
    stamp=path.stat();key=(stamp.st_size,stamp.st_mtime_ns,tuple(addresses))
    with LOCK:
        packet_lock=owner.setdefault('packet_lock',threading.Lock())
    with packet_lock:
        if owner.get('packet_cache_key')!=key:
            owner['packet_cache']=network.analyze_capture(path,addresses);owner['packet_cache_key']=key
        return path,owner['packet_cache']


def packet_descriptor(data,q):
    number=int(q.get('number','0'))
    if data is None or not 1<=number<=len(data['packets']):raise ValueError('Select an available packet')
    return data['packets'][number-1]


def make_audio(item):
    with item['audio_lock']:
        out = item.setdefault('audio_path', Path(WORK.name)/(secrets.token_hex(16)+'.wav'))
        if out.exists():
            return out
        ffmpeg = shutil.which('ffmpeg')
        if not ffmpeg:
            raise ValueError('Install FFmpeg for waveform decoding and sample inspection. Original playback may still work.')
        # Bounded preview; originals remain available in full through the media player.
        run = subprocess.run([ffmpeg, '-v', 'error', '-nostdin', '-y', '-protocol_whitelist', 'file,pipe',
                              '-i', str(item['path']), '-t', '300', '-vn', '-ac', '2', '-ar', '22050',
                              '-c:a', 'pcm_s16le', str(out)], capture_output=True, timeout=90)
        if run.returncode:
            out.unlink(missing_ok=True)
            raise ValueError('Audio decode failed: '+run.stderr.decode('utf-8', 'replace')[-1500:])
        return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def sendbytes(self, data, mime='application/json', status=200, attachment=None):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        if attachment:self.send_header('Content-Disposition', f'attachment; filename="{attachment}"')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self' blob:; frame-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)
    def json(self, obj, status=200):
        self.sendbytes(json.dumps(obj).encode(), status=status)
    def validhost(self):
        return self.headers.get('Host') == f'127.0.0.1:{self.server.server_port}'
    def do_GET(self):
        if not self.validhost():
            return self.json(dict(error='Invalid host'), 403)
        try:
            u = urlparse(self.path)
            q = {k:v[0] for k,v in parse_qs(u.query).items()}
            if u.path in ('/', '/app.js', '/style.css','/telemetry.js','/editor.js','/media-tools.js','/everyday.js'):
                path = ROOT / {'/':'index.html', '/app.js':'app.js', '/style.css':'style.css','/telemetry.js':'telemetry.js','/editor.js':'editor.js','/media-tools.js':'media-tools.js','/everyday.js':'everyday.js'}[u.path]
                return self.sendbytes(path.read_bytes(), mimetypes.guess_type(str(path))[0] or 'text/plain')
            if u.path == '/api/url/play':return STREAMS.proxy(self,q.get('stream'))
            if u.path == '/api/url/transcode':return STREAMS.transcode(self,q.get('stream'))
            if u.path == '/api/imaging/providers':return self.json(imaging.providers())
            if u.path == '/api/imaging/status':return self.json(IMAGING.status(q.get('job')))
            if u.path == '/api/tasks/status':return self.json(TASKS.status(q.get('job')))
            if u.path == '/api/tasks/download':return self.stream(TASKS.download(q.get('job')),'converted-files.zip',attachment=True)
            if u.path == '/api/config':
                return self.json(dict(token=TOKEN, limit=LIMIT, ffmpeg=bool(shutil.which('ffmpeg'))))
            if u.path == '/api/hardware/monitor':
                return self.json(hardware.monitor())
            if u.path == '/api/hardware/inventory':
                return self.json(hardware.inventory(q.get('section','hardware')))
            if u.path == '/api/network/interfaces':
                return self.json(CAPTURES.interfaces())
            if u.path == '/api/network/status':
                return self.json(CAPTURES.status(q.get('capture')))
            if u.path == '/api/capture/download':
                return self.stream(CAPTURES.path(q.get('capture')), 'capture.pcapng',attachment=True)
            if u.path in ('/api/packets','/api/packet','/api/packet/payload','/api/conversation','/api/packet/deep'):
                path,data=packet_source(q)
                if u.path=='/api/packets':
                    return self.json(data or dict(packets=[],flows=[],protocols={},summary=dict(packets=0),local_ips=[],warnings=[],note='Waiting for the first captured packet'))
                if u.path=='/api/conversation':
                    value=network.conversation_data(path,data['packets'],q.get('flow'))
                    if q.get('download'):
                        return self.sendbytes(json.dumps(value,indent=2).encode(),'application/json',attachment='conversation.json')
                    return self.json(value)
                descriptor=packet_descriptor(data,q)
                if u.path=='/api/packet/deep':return self.json(network.deep_dissection(path,descriptor['number']))
                value=network.packet_detail(path,descriptor,data['local_ips'])
                if u.path=='/api/packet/payload':
                    return self.sendbytes(bytes.fromhex(value['payload_hex']),'application/octet-stream',attachment=f'packet-{descriptor["number"]}-payload.bin')
                return self.json(value)
            item = FILES.get(q.get('id'))
            if item is None:
                return self.json(dict(error='File session not found'), 404)
            path = item['path']
            if u.path == '/api/rom/info':return self.json(discrom.rom_info(path,item['data']['name']))
            if u.path == '/api/disc/info':return self.json(discrom.disc_info(path))
            if u.path == '/api/info':
                return self.json(dict(id=q['id'], **item['data']))
            if u.path == '/api/download':
                return self.stream(path,item['data']['name'],attachment=True)
            if u.path == '/api/provenance':
                return self.json(dict(chain=[dict(id=ident,name=ancestor['data']['name'],kind=ancestor['data']['kind'],format=ancestor['data']['format'],size=ancestor['data']['size'],sha256=ancestor['data']['sha256'],provenance=ancestor['data']['provenance']) for ident,ancestor in reversed(list(navigation.ancestors(FILES,q['id'])))],budget=NAVIGATION_BUDGET.usage()))
            if u.path == '/api/embedded':
                everyday.source_check(path,item['data'])
                return self.json(navigation.filter_scan(path,embedded.scan(path),FILES,q['id']))
            if u.path == '/api/model':
                return self.json(mesh_data(path, item['data']['name']))
            if u.path == '/api/events':
                if os.name != 'nt' or not shutil.which('wevtutil'):
                    raise ValueError('Readable EVTX export requires Windows wevtutil. Raw bytes and strings remain available.')
                run=subprocess.run(['wevtutil','qe',str(path),'/lf:true','/f:xml','/c:2000'],
                                   capture_output=True,timeout=30)
                if run.returncode:
                    raise ValueError(run.stderr.decode('utf-8','replace')[-1500:])
                raw=run.stdout
                text=raw.decode('utf-16' if raw[:2] in (b'\xff\xfe',b'\xfe\xff') else 'utf-8','replace')
                return self.json(dict(text=text,note='First 2,000 event records, exported through Windows wevtutil.'))
            if u.path == '/api/hex':
                off = max(0, int(q.get('offset', 0)))
                length = min(4096, max(0, int(q.get('length', 512))))
                with path.open('rb') as f:
                    f.seek(off)
                    data = f.read(length)
                return self.json(dict(offset=off, hex=data.hex(), total=path.stat().st_size))
            if u.path == '/api/text':
                with path.open('rb') as f:
                    data = f.read(1024*1024)
                return self.json(dict(text=data.decode('utf-16' if data[:2] in (b'\xff\xfe',b'\xfe\xff') else 'utf-8-sig', 'replace'), truncated=path.stat().st_size>len(data)))
            if u.path == '/api/strings':
                # Bounded scan, with offsets; ASCII strings and aligned UTF-16LE ASCII strings.
                with path.open('rb') as f:
                    data = f.read(16*1024*1024)
                entries=[]
                for pat, encoding in ((rb'[\x20-\x7e]{4,}', 'ascii'), (rb'(?:[\x20-\x7e]\x00){4,}', 'utf-16le')):
                    for match in re.finditer(pat, data):
                        entries.append(dict(offset=match.start(), encoding=encoding, text=match.group()[:1000].decode(encoding)))
                        if len(entries) >= 5000:
                            break
                    if len(entries) >= 5000:
                        break
                return self.json(dict(strings=sorted(entries, key=lambda x:x['offset']), scanned=len(data), capped=len(entries)>=5000))
            if u.path == '/api/waveform':
                audio = make_audio(item)
                with wave.open(str(audio), 'rb') as w:
                    count = w.getnframes()
                    channels = w.getnchannels()
                    step = max(1, math.ceil(count/1200))
                    peaks = []
                    for i in range(0, count, step):
                        block = w.readframes(step)
                        values = struct.unpack('<'+'h'*(len(block)//2), block)
                        peaks.append([min(values, default=0)/32768, max(values, default=0)/32768])
                    return self.json(dict(peaks=peaks, duration=count/w.getframerate(), rate=w.getframerate(),
                                          channels=channels, note='Preview: first 300 seconds, decoded to 22,050 Hz stereo PCM16.'))
            if u.path == '/api/samples':
                off = max(0, int(q.get('offset', 0)))
                # Native PCM16 WAV data remains exact; other formats use the labelled decode preview.
                native = False
                try:
                    w = wave.open(str(path), 'rb')
                    native = w.getsampwidth() == 2 and w.getcomptype() == 'NONE'
                    if not native:
                        w.close()
                except (wave.Error, EOFError):
                    pass
                if not native:
                    w = wave.open(str(make_audio(item)), 'rb')
                with w:
                    off = min(off, w.getnframes())
                    w.setpos(off)
                    raw = w.readframes(128)
                    vals = struct.unpack('<'+'h'*(len(raw)//2), raw)
                    c = w.getnchannels()
                    return self.json(dict(offset=off, rate=w.getframerate(), channels=c, total=w.getnframes(),
                        source='Original PCM16 samples' if native else 'Decoded preview: 22,050 Hz stereo PCM16; not original encoded bytes',
                        samples=[list(vals[i:i+c]) for i in range(0,len(vals),c)]))
            if u.path == '/api/raw':
                return self.stream(path, item['data']['name'])
            if u.path == '/api/audio':
                return self.stream(make_audio(item), 'preview.wav')
            return self.json(dict(error='Not found'), 404)
        except (ValueError, OSError, EOFError, wave.Error, subprocess.TimeoutExpired, struct.error, KeyError, IndexError) as e:
            self.json(dict(error=str(e)), 400)

    def stream(self, path, name, attachment=False):
        size = path.stat().st_size
        start, end = 0, size-1
        range_header = self.headers.get('Range')
        status = 200
        if range_header:
            match = re.fullmatch(r'bytes=(\d*)-(\d*)', range_header)
            if not match or not size:
                return self.sendbytes(b'', status=416)
            a, b = match.groups()
            if a:
                start = int(a)
                end = min(int(b), size-1) if b else size-1
            elif b and int(b)>0:
                start = max(0, size-int(b))
            else:
                return self.sendbytes(b'', status=416)
            if start >= size or end < start:
                return self.sendbytes(b'', status=416)
            status = 206
        self.send_response(status)
        self.send_header('Content-Type', mimetypes.guess_type(name)[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(max(0,end-start+1)))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "sandbox; default-src 'none'")
        if attachment:
            safe_name=re.sub(r'[\r\n"\\]','_',name)[:200]
            ascii_name=safe_name.encode('ascii','replace').decode().replace('?','_')
            self.send_header('Content-Disposition', f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(safe_name,safe="")}')
        if status == 206:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        self.end_headers()
        with path.open('rb') as f:
            f.seek(start)
            remaining = end-start+1
            while remaining>0:
                data = f.read(min(65536, remaining))
                if not data:
                    break
                self.wfile.write(data)
                remaining -= len(data)

    def do_POST(self):
        if not self.validhost() or self.headers.get('X-EOX-Token') != TOKEN:
            return self.json(dict(error='Invalid session token'), 403)
        u = urlparse(self.path)
        q = {k:v[0] for k,v in parse_qs(u.query).items()}
        try:
            if u.path in ('/api/tasks/start','/api/archive/create'):
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=1024**2:raise ValueError('Invalid task settings')
                args=json.loads(self.rfile.read(length))
                if u.path=='/api/tasks/start':
                    ids=args.get('ids',[])
                    if not isinstance(ids,list) or any(i not in FILES for i in ids):raise ValueError('Choose opened session files')
                    return self.json(TASKS.start([FILES[i] for i in ids],args))
                additions=resolve_additions(args.get('add',[]));args['add']=additions
                out,name,report=everyday.repack_archive(None,None,args,WORK.name)
                result=register(out,name);result['edit_report']=report;return self.json(result)
            if u.path=='/api/tasks/cancel':return self.json(TASKS.cancel(q.get('job')))
            if u.path in ('/api/url/resolve','/api/imaging/start'):
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:raise ValueError('Invalid settings size')
                settings=json.loads(self.rfile.read(length))
                if u.path=='/api/url/resolve':return self.json(STREAMS.resolve(settings.get('url'),settings.get('mode','auto')))
                if settings.get('source_id'):
                    source=FILES.get(settings['source_id'])
                    if not source:raise ValueError('File session not found')
                    settings.update(mode='file',source=str(source['path']),display_name=source['data']['name'])
                return self.json(IMAGING.start(settings))
            if u.path=='/api/url/stop':return self.json(STREAMS.stop(q.get('stream')))
            if u.path=='/api/imaging/cancel':return self.json(IMAGING.cancel(q.get('job')))
            if u.path in ('/api/rom/fix','/api/rom/ips','/api/disc/extract','/api/disc/replace'):
                item=FILES.get(q.get('id'))
                if not item:raise ValueError('File session not found')
                path=item['path'];name=item['data']['name']
                # Direct-path sources may have changed since inspection; refresh before changes.
                digest=hashlib.sha256()
                with path.open('rb') as f:
                    while block:=f.read(1024**2):digest.update(block)
                if digest.hexdigest()!=item['data']['sha256']:raise ValueError('Source changed since opening. Reopen it before creating a modified copy.')
                if u.path=='/api/rom/fix':out,name=discrom.fix_rom(path,name,WORK.name)
                elif u.path=='/api/rom/ips':
                    length=int(self.headers.get('Content-Length','0'))
                    if not 0<length<=16*1024**2:raise ValueError('IPS patch limit is 16 MiB')
                    out,count=discrom.apply_ips(path,self.rfile.read(length),WORK.name)
                    name=Path(name).stem+'-patched'+Path(name).suffix
                else:
                    entries=discrom.disc_info(path)['entries'];index=int(q.get('index','-1'))
                    if not 0<=index<len(entries):raise ValueError('Disc entry not found')
                    entry=entries[index]
                    if u.path=='/api/disc/extract':
                        out=Path(WORK.name)/secrets.token_hex(16);name=entry['name'].split(';')[0]
                        if entry['size']>EXTRACT_LIMIT:raise ValueError('Navigation member limit is 64 MiB')
                        with NAVIGATION_BUDGET.reserve(entry['size']) as lease:
                            try:
                                discrom.extract_disc(path,entry,out)
                                if out.stat().st_size!=entry['size']:raise ValueError('Disc member size differs from its metadata')
                                storage=navigation.slice_range(q['id'],item,entry['offset'],entry['size']) if entry.get('offset') is not None else None
                                result=register(out,name,parent_id=q['id'],origin=dict(relation='member',member=entry['name'],member_index=index,storage_range=storage,encoding='Disc filesystem member'))
                                lease['committed']=True
                            except Exception:
                                out.unlink(missing_ok=True);raise
                        return self.json(result)
                    else:
                        length=int(self.headers.get('Content-Length','0'))
                        if not 0<=length<=64*1024**2:raise ValueError('Replacement limit is 64 MiB')
                        out=discrom.replace_iso(path,entry,self.rfile.read(length),WORK.name);name=Path(name).stem+'-edited.iso'
                return self.json(register(out,name))
            if u.path in ('/api/editor/info','/api/editor/apply'):
                item=FILES.get(q.get('id'))
                if not item:raise ValueError('File session not found')
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16*1024**2:raise ValueError('Edit request must be at most 16 MiB')
                args=json.loads(self.rfile.read(length));tool=args.pop('tool','')
                if tool=='archive' and u.path=='/api/editor/apply':args['add']=resolve_additions(args.get('add',[]))
                try:
                    if u.path=='/api/editor/info':return self.json(editing.describe_editor(item['path'],item['data'],tool,args))
                    out,name,report=editing.apply_edit(item['path'],item['data'],tool,args,WORK.name)
                    result=register(out,name)
                    result['edit_report']=report;result['source_id']=q['id']
                    FILES[result['id']]['data'].update(edit_report=report,source_id=q['id'])
                    return self.json(result)
                except Exception as e:
                    raise ValueError(str(e)) from e
            if u.path == '/api/network/start':
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:raise ValueError('Invalid capture settings')
                settings=json.loads(self.rfile.read(length))
                return self.json(CAPTURES.start(settings.get('interface'),settings.get('duration',120),settings.get('filter','')))
            if u.path == '/api/network/stop':
                return self.json(CAPTURES.stop(q.get('capture')))
            if u.path in ('/api/packet/open','/api/conversation/open'):
                path,data=packet_source(q)
                if u.path == '/api/packet/open':
                    descriptor=packet_descriptor(data,q)
                    value=network.packet_detail(path,descriptor,data['local_ips'])
                    raw=bytes.fromhex(value['payload_hex']);name=f'packet-{descriptor["number"]}-payload.bin'
                else:
                    value=network.conversation_data(path,data['packets'],q.get('flow'))
                    side=q.get('side','a_to_b');index=int(q.get('segment','0'))
                    segment=value['directions'][side]['segments'][index]
                    raw=bytes.fromhex(segment['hex']);name=f'conversation-{side}-{index}.bin'
                out=Path(WORK.name)/secrets.token_hex(16);out.write_bytes(raw)
                return self.json(register(out,name))
            if u.path == '/api/open-path':
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:
                    raise ValueError('Invalid path request')
                requested=json.loads(self.rfile.read(length))['path']
                path=Path(requested).expanduser().resolve(strict=True)
                if not path.is_file():
                    raise ValueError('Path must name a regular file')
                data=register(path,path.name)
                data['direct_path']=True
                FILES[data['id']]['data']['direct_path']=True
                return self.json(data)
            if u.path == '/api/slice/open':
                item=FILES.get(q.get('id'))
                if not item:raise ValueError('File session not found')
                offset=int(q.get('offset','0'))
                if not 0<=offset<item['path'].stat().st_size:raise ValueError('Candidate offset is outside the file')
                candidate=None;fmt=q.get('format')
                if fmt:
                    if fmt not in ('bmp','png','wav','webp','avi','zip'):raise ValueError('No exact-boundary reader for this format; use raw byte opening')
                    with item['path'].open('rb') as f:
                        f.seek(offset);sample=f.read(138 if fmt=='bmp' else EXTRACT_LIMIT)
                    candidate=embedded.object_at(sample,0,fmt,item['path'].stat().st_size-offset)
                    if not candidate:raise ValueError('No validated '+fmt.upper()+' object boundary at this offset within the 64 MiB extraction window. Raw views remain available.')
                    if not candidate['complete']:raise ValueError(fmt.upper()+' is truncated; its declared bytes exceed the parent file. Raw hex/text remains available.')
                    if candidate['size']>EXTRACT_LIMIT:raise ValueError('Object extraction limit is 64 MiB; inspect the parent through its byte views')
                    length=candidate['size']
                else:length=max(0,min(EXTRACT_LIMIT,int(q.get('length',str(EXTRACT_LIMIT)))))
                length=min(length,item['data']['size']-offset)
                coordinate=navigation.slice_range(q['id'],item,offset,length)
                # Refuse an exact range even when a caller bypasses Embedded UI.
                for _,ancestor in navigation.ancestors(FILES,q['id']):
                    if coordinate==ancestor['data']['provenance']['byte_range']:
                        raise navigation.CycleError('Recursion blocked: whole-object byte range is the current object or an ancestor. Use Structure to open members.')
                out=Path(WORK.name)/secrets.token_hex(16)
                with NAVIGATION_BUDGET.reserve(length) as lease:
                    try:
                        everyday.source_check(item['path'],item['data'])
                        with item['path'].open('rb') as f:f.seek(offset);raw=f.read(length)
                        if len(raw)!=length:raise ValueError('Source changed or object is truncated. Reopen the source.')
                        out.write_bytes(raw)
                        name=f'{item["data"]["name"]}-offset-{offset}'+('.'+fmt if candidate else '.bin')
                        result=register(out,name,parent_id=q['id'],origin=dict(relation='embedded',offset=offset))
                        if candidate:
                            report=dict(source_id=q['id'],offset=offset,length=length,boundary=candidate['boundary'],validation=candidate['validation'])
                            result['carve_report']=report;FILES[result['id']]['data']['carve_report']=report
                        lease['committed']=True
                    except Exception:
                        out.unlink(missing_ok=True);raise
                return self.json(result)
            if u.path == '/api/open':
                size = int(self.headers.get('Content-Length', '-1'))
                if not 0 <= size <= LIMIT:
                    return self.json(dict(error='This build accepts files up to 2 GiB'), 413)
                name = unquote(self.headers.get('X-File-Name', 'file.bin')).replace('\\','/').split('/')[-1]
                path = Path(WORK.name) / secrets.token_hex(16)
                self.connection.settimeout(60)
                with path.open('wb') as f:
                    remaining=size
                    while remaining:
                        data = self.rfile.read(min(1024*1024, remaining))
                        if not data:
                            raise ValueError('Incomplete file transfer')
                        f.write(data)
                        remaining -= len(data)
                return self.json(register(path, name))
            if u.path == '/api/extract':
                item = FILES.get(q.get('id'))
                if not item:
                    raise ValueError('File session not found')
                if item['data']['kind'] != 'archive':
                    raise ValueError('Not an archive')
                index = int(q.get('index', '-1'))
                entries = item['data']['entries']
                if not 0 <= index < len(entries):
                    raise ValueError('Invalid entry')
                entry=entries[index]
                if entry.get('directory') or entry['size'] > EXTRACT_LIMIT or entry.get('encrypted'):
                    raise ValueError('Only unencrypted files up to 64 MiB can be opened from a container')
                out=Path(WORK.name)/secrets.token_hex(16)
                origin=dict(relation='member',member=entry['name'],member_index=index)
                with NAVIGATION_BUDGET.reserve(entry['size']) as lease:
                    try:
                        everyday.source_check(item['path'],item['data'])
                        if item['data']['format']=='ZIP container':
                            with zipfile.ZipFile(item['path']) as z:
                                members=z.infolist();member=members[index]
                                if member.file_size!=entry['size'] or member.filename!=entry['name']:raise ValueError('Archive metadata changed; reopen the source')
                                with item['path'].open('rb') as f:
                                    f.seek(member.header_offset);local=f.read(30)
                                if len(local)!=30 or local[:4]!=b'PK\x03\x04':raise ValueError('Invalid ZIP local header')
                                names,extra=struct.unpack_from('<HH',local,26)
                                data_offset=member.header_offset+30+names+extra
                                if data_offset+member.compress_size>z.start_dir:raise ValueError('ZIP member overlaps the central directory')
                                origin.update(storage_range=navigation.slice_range(q['id'],item,data_offset,member.compress_size),encoding='ZIP method '+str(member.compress_type))
                                with z.open(member) as source,out.open('wb') as dest:self.copybounded(source,dest,entry['size'])
                        elif item['data']['format'] in ('RAR container','7z container'):
                            origin['encoding']='Provider-decoded member; physical range unavailable'
                            everyday.read_external(item['path'],entry['name'],out,size_limit=min(EXTRACT_LIMIT,entry['size']))
                        else:
                            if not entry.get('regular'):raise ValueError('Links and special TAR entries are listed but not extracted')
                            with tarfile.open(item['path']) as t:
                                for i,member in enumerate(t):
                                    if i==index:
                                        if not member.isfile() or member.size!=entry['size'] or member.name!=entry['name']:raise ValueError('Invalid or changed TAR member metadata')
                                        origin['encoding']='TAR member'
                                        # TAR stream positions are physical only for uncompressed TAR.
                                        with item['path'].open('rb') as f:magic=f.read(6)
                                        if not magic.startswith((b'\x1f\x8b',b'BZh',b'\xfd7zXZ')):
                                            origin['storage_range']=navigation.slice_range(q['id'],item,member.offset_data,member.size)
                                        else:origin['encoding']='Compressed TAR; member offset is in decoded stream';origin['decoded_stream_offset']=member.offset_data
                                        with t.extractfile(member) as source,out.open('wb') as dest:self.copybounded(source,dest,entry['size'])
                                        break
                                else:raise ValueError('TAR member missing')
                        if out.stat().st_size!=entry['size']:raise ValueError('Decoded member length differs from container metadata')
                        result=register(out,entry['name'],parent_id=q['id'],origin=origin)
                        lease['committed']=True
                    except Exception:
                        out.unlink(missing_ok=True);raise
                return self.json(result)
            return self.json(dict(error='Not found'), 404)
        except (ValueError, OSError, EOFError, zipfile.BadZipFile, tarfile.TarError, RuntimeError, NotImplementedError, subprocess.TimeoutExpired, KeyError, TypeError, IndexError) as e:
            self.json(dict(error=str(e)), 400)
    @staticmethod
    def copybounded(source, dest, expected_size=None):
        total=0
        while data := source.read(65536):
            total+=len(data)
            if total>EXTRACT_LIMIT or (expected_size is not None and total>expected_size):
                raise ValueError('Decompressed entry exceeds its declared size or 64 MiB limit')
            dest.write(data)
        if expected_size is not None and total!=expected_size:raise ValueError('Decompressed entry is shorter than its declared size')


def main():
    global NAVIGATION_BUDGET
    ap=argparse.ArgumentParser(description='EOX — Every Object eXposed')
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--no-browser', action='store_true')
    ap.add_argument('--navigation-budget-mib',type=int,default=512,help='Cumulative decoded navigation byte budget (default: 512 MiB)')
    ap.add_argument('--navigation-max-objects',type=int,default=10000,help='Maximum opened navigation children per session')
    args=ap.parse_args()
    if args.navigation_budget_mib<=0 or args.navigation_max_objects<=0:ap.error('Navigation budgets must be positive')
    NAVIGATION_BUDGET=navigation.NavigationBudget(max_bytes=args.navigation_budget_mib*1024**2,max_objects=args.navigation_max_objects)
    server=ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    url=f'http://127.0.0.1:{server.server_port}'
    print(f'EOX running at {url}\nKeep this window open. Ctrl+C stops EOX.', flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        CAPTURES.close()
        STREAMS.close()
        IMAGING.close()
        TASKS.close()
        server.server_close()
        WORK.cleanup()


if __name__ == '__main__':
    main()
