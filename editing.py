"""Format-aware capabilities and basic edits. Every operation creates a new copy."""
import csv
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path
import secrets
import shutil
import subprocess
import zipfile
import everyday

EDIT_LIMIT=64*1024**2
TEXT_LIMIT=4*1024**2


def available(name):
    return importlib.util.find_spec(name) is not None


def capabilities(path,data):
    kind=data['kind'];name=data['name'];ext=Path(name).suffix.lower();size=data['size']
    layers=['Bytes','Text interpretation','Readable strings','Embedded signatures']
    tools=[dict(id='hex',label='Patch byte range',ready=True,
                detail='Replace bytes at an offset without changing file length; writes a copy. Raw patches do not repair checksums, signatures or internal offsets.')]
    interpretation='Raw bytes; no semantic format has been established.'
    evidence='Content sniffing; file extension is a hint.'
    subtype=data['format'];notes=[]
    if kind=='text':
        layers+=['Editable text'];interpretation='Readable text'
        structured=data.get('structured',{}).get('type')
        if structured=='JSON':subtype='JSON document';layers+=['JSON formatted source']
        elif structured=='Delimited table':subtype='TSV table' if ext=='.tsv' else 'CSV table';layers+=['Rows and columns']
        elif structured:subtype=structured
        ready=size<=TEXT_LIMIT
        tools.insert(0,dict(id='text',label='Edit text',ready=ready,detail='Lossless decoding required. Preserves detected UTF BOM/encoding and line endings unless edited. Full-file limit: 4 MiB.'))
        if structured=='JSON':tools.insert(0,dict(id='json',label='Edit / validate JSON',ready=ready,detail='Validate, format or minify JSON; preserves text encoding.'))
        if structured=='Delimited table':tools.insert(0,dict(id='table',label='Edit table',ready=ready,detail='Edit cells / add rows / remove rows; exports CSV or TSV in the selected delimiter. Formatting and quoting may change.'))
    elif kind=='archive':
        tools.insert(0,dict(id='archive',label='Add / remove files · repack archive',ready=data['format'] in ('ZIP container','TAR container') or bool(everyday.sevenzip()),detail='Add files, remove entries, export ZIP/TAR/TAR.GZ; 7z/RAR use local writer providers. 256 MiB per member, 1 GiB expanded.'))
        layers+=['Container entries'];interpretation='Archive container'
        names=[e['name'] for e in data.get('entries',[])]
        for prefix,label in [('word/','Word document package'),('xl/','Excel workbook package'),('ppt/','PowerPoint presentation package')]:
            if '[Content_Types].xml' in names and any(n.startswith(prefix) for n in names):subtype=label;notes.append('Package/container views remain available.');break
        if subtype=='Word document package':tools.insert(0,dict(id='docx',label='Edit DOCX paragraphs',ready=available('lxml') and size<=EDIT_LIMIT,detail='Change body/table/header/footer paragraph text, retaining existing runs and untouched package parts. Fields and tracked changes are listed separately.'))
        if 'AndroidManifest.xml' in names:subtype='Android APK package';notes.append('Changes invalidate APK signatures; this tool does not rebuild or sign apps.')
        if data['format']=='ZIP container':
            tools.append(dict(id='zip',label='Replace ZIP entry text',ready=size<=EDIT_LIMIT and not any(e.get('encrypted') for e in data.get('entries',[])),
                detail='Replace one UTF text entry in a new archive; member names and ZIP metadata retained. Repacked packages may invalidate signatures.'))
    elif kind=='pdf':
        tools.insert(0,dict(id='pdftext',label='Correct PDF text',ready=available('pymupdf') and size<=EDIT_LIMIT,detail='Click a word on a rendered page and replace its text. Uses source font where available, otherwise a standard font. Preview before saving; scanned pages need OCR.'))
        layers+=['PDF pages'];interpretation='PDF document';evidence='PDF content signature'
        tools.append(dict(id='pdf',label='Select / reorder / rotate PDF pages',ready=available('pypdf') and size<=EDIT_LIMIT,
            detail='Optional pypdf provider. Page-level editing; does not rewrite page text. Password required when encrypted. Output is unencrypted; document-level forms, links and signatures may not survive extraction.'))
    elif kind=='image':
        tools.insert(0,dict(id='imageformat',label='Convert image / strip metadata',ready=available('PIL') and size<=EDIT_LIMIT,detail='PNG/JPG/WebP/BMP/TIFF export; rotate and resize; metadata stripped. First frame. Batch conversions are in Everyday tasks.'))
        layers+=['Raster pixels'];interpretation='Raster image';evidence='Image content signature'
        tools.append(dict(id='image',label='Crop / rotate / resize image',ready=available('PIL') and size<=EDIT_LIMIT,
            detail='Optional Pillow provider. First frame only; exported as PNG. Animation and source metadata are not preserved.'))
    elif kind in ('audio','video'):
        tools.insert(0,dict(id='convert',label='Convert full file / trim / audio extraction',ready=bool(shutil.which('ffmpeg')),detail='Full file by default. WAV/MP3/FLAC/Ogg/M4A and MP4/WebM export. Optional start/duration/gain/rate/channel controls. Runs as a cancellable job.'))
        layers+=['Media streams','Playback'];interpretation='Media container / stream'
        tools.append(dict(id='audio',label='Trim / gain audio → WAV',ready=bool(shutil.which('ffmpeg')),
            detail='Decoded PCM16 audio export; start/duration/gain controls. For video, exports audio only. No video timeline editor.'))
    elif kind=='model':
        layers+=['Geometry'] if data.get('model_supported') else []
        interpretation='3D asset'
        if ext in ('.obj','.gltf') and size<=TEXT_LIMIT:
            tools.insert(0,dict(id='text',label='Edit model source',ready=True,detail='Text source editing; subsequent rendering verifies what the mesh parser can read.'))
        notes.append('3D preview uses geometry; this is not a vertex sculpting or material editor.')
    elif kind=='rom':
        layers+=['Cartridge headers','Platform checksum checks'];interpretation='ROM / cartridge image candidate'
        notes.append('ROM tools tab: verified file clone, classic IPS patch and GB/GBC/GBA checksum repair. Other formats retain byte editing.')
    elif kind=='disc':
        layers+=['Logical sectors','Filesystem entries where parsed'];interpretation='Disc image / track-container candidate'
        notes.append('Disc tools tab: verified clone, filesystem entry extraction and copy replacement where parsed. Raw-sector containers and encryption may require extra providers.')
    elif kind=='pe':
        layers+=['PE sections','Imports / exports','Resources'];interpretation='Windows PE binary'
        subtype='Windows kernel driver' if ext=='.sys' else 'Windows DLL' if ext=='.dll' else 'Windows executable / PE binary'
        evidence='MZ and PE signatures plus parsed PE header'
        notes.append('Raw byte edits only. EOX does not rebuild executable code, repair PE structures or re-sign binaries.')
    elif kind=='packets':
        layers+=['Packet records','Protocol layers','Conversation payloads'];interpretation='Network capture'
        notes.append('Extract payloads for editing as separate files. Byte patches do not recalculate packet checksums or capture-record lengths.')
    elif kind in ('crash','eventlog'):
        layers+=['Diagnostic records'];interpretation='Diagnostic artifact'
        notes.append('Decoded diagnostic records are inspection views; raw byte editing creates a separate copy.')
    return dict(subtype=subtype,interpretation=interpretation,evidence=evidence,extension=ext or '(none)',
                layers=layers,tools=tools,notes=notes,policy='Edits create new session copies. Download the result to keep it. Originals are not overwritten.')


def decode_text(raw):
    if raw.startswith(b'\xff\xfe'):return raw[2:].decode('utf-16le'), 'utf-16le',b'\xff\xfe'
    if raw.startswith(b'\xfe\xff'):return raw[2:].decode('utf-16be'), 'utf-16be',b'\xfe\xff'
    if raw.startswith(b'\xef\xbb\xbf'):return raw[3:].decode('utf-8'), 'utf-8',b'\xef\xbb\xbf'
    return raw.decode('utf-8'), 'utf-8',b''


def text_document(path):
    if path.stat().st_size>TEXT_LIMIT:raise ValueError('Full text editing is limited to 4 MiB. Byte inspection remains available.')
    value,encoding,bom=decode_text(path.read_bytes())
    return dict(text=value,encoding=encoding,bom=bool(bom),line_endings='CRLF' if '\r\n' in value else 'LF' if '\n' in value else 'None')


def load_pdf(path,password=''):
    if not available('pypdf'):raise ValueError('Install optional pypdf to use PDF page tools. The browser PDF view and raw layers remain available.')
    from pypdf import PdfReader
    reader=PdfReader(str(path))
    if reader.is_encrypted and not reader.decrypt(password):raise ValueError('This PDF needs its correct password. Raw inspection remains available.')
    return reader


def describe_editor(path,data,tool,args):
    if tool=='docx':return everyday.describe_docx(path)
    if tool=='pdftext':return everyday.describe_pdf(path,args)
    if tool=='archive':return dict(entries=everyday.archive_entries(path),sevenzip=bool(everyday.sevenzip()),rar=bool(shutil.which('rar')))

    if tool in ('text','json','table'):
        d=text_document(path)
        if tool=='table':
            delim='\t' if Path(data['name']).suffix.lower()=='.tsv' else ','
            try:delim=csv.Sniffer().sniff(d['text'][:8192],delimiters=',\t;|').delimiter
            except csv.Error:pass
            rows=list(csv.reader(io.StringIO(d['text'],newline=''),delimiter=delim))
            if len(rows)>2000 or any(len(r)>100 for r in rows):raise ValueError('Table editing is limited to 2,000 rows and 100 columns. Full text editing remains available.')
            d.update(rows=rows,delimiter=delim)
        return d
    if tool=='zip':
        index=int(args.get('index',0))
        with zipfile.ZipFile(path) as z:
            infos=z.infolist()
            if not 0<=index<len(infos):raise ValueError('Select an archive member')
            info=infos[index]
            if info.is_dir() or info.flag_bits&1 or info.file_size>TEXT_LIMIT:raise ValueError('Entry text editing requires an unencrypted UTF text file up to 4 MiB.')
            text,encoding,bom=decode_text(z.read(info))
            return dict(index=index,name=info.filename,text=text,encoding=encoding,bom=bool(bom))
    if tool=='pdf':
        reader=load_pdf(path,args.get('password',''))
        return dict(pages=len(reader.pages),encrypted=reader.is_encrypted,metadata={str(k):str(v) for k,v in (reader.metadata or {}).items()})
    if tool=='image':
        if not available('PIL'):raise ValueError('Install optional Pillow to use image tools. Browser preview remains available.')
        from PIL import Image
        with Image.open(path) as im:return dict(width=im.width,height=im.height,format=im.format,mode=im.mode,frames=getattr(im,'n_frames',1))
    return dict(note='Enter edit parameters, then generate a preview copy.')


def new_name(name,suffix=None):
    p=Path(name);return p.stem+'-edited'+(suffix if suffix is not None else p.suffix)


def apply_edit(path,data,tool,args,folder):
    # Readable edits are offered by capability; raw patching is always available.
    tools={t['id']:t for t in capabilities(path,data)['tools']}
    if tool not in tools or not tools[tool]['ready']:raise ValueError('This edit needs its provider or a smaller input; raw inspection remains available.')
    if args.get('base_sha256')!=data['sha256']:raise ValueError('Editor base does not match the opened file. Reopen it before editing.')
    if tool in ('archive','docx','pdftext','imageformat'):
        if tool!='archive' and path.stat().st_size>EDIT_LIMIT:raise ValueError('Document/image editing limit is 64 MiB')
        everyday.source_check(path,data)
        functions={'archive':everyday.repack_archive,'docx':everyday.edit_docx,'pdftext':everyday.edit_pdf_word,'imageformat':everyday.image_export}
        return functions[tool](path,data,args,folder)
    output=Path(folder)/(secrets.token_hex(16)+'.edit');name=new_name(data['name']);report={}
    try:
        if tool=='hex':
            offset=int(args.get('offset',0));replacement=bytes.fromhex(str(args.get('hex','')))
            if not replacement or len(replacement)>1024**2:raise ValueError('Patch must contain 1 byte to 1 MiB of hexadecimal data')
            if offset<0 or offset+len(replacement)>data['size']:raise ValueError('Patch is outside the existing file. Length-changing edits are not provided.')
            digest=hashlib.sha256();position=0
            with path.open('rb') as src,output.open('wb') as dst:
                while block:=src.read(1024**2):
                    digest.update(block);end=position+len(block)
                    a=max(offset,position);b=min(offset+len(replacement),end)
                    if a<b:block=block[:a-position]+replacement[a-offset:b-offset]+block[b-position:]
                    dst.write(block);position=end
            if digest.hexdigest()!=data['sha256']:raise ValueError('Source changed since it was opened. Reopen it before editing.')
            report=dict(offset=offset,replaced_bytes=len(replacement),length_changed=False)
        else:
            if path.stat().st_size>EDIT_LIMIT and tool!='audio':raise ValueError('Structured editing is limited to 64 MiB inputs')
            digest=hashlib.sha256()
            with path.open('rb') as f:
                while block:=f.read(1024**2):digest.update(block)
            if digest.hexdigest()!=data['sha256']:raise ValueError('Source changed since it was opened. Reopen it before editing.')
            if tool in ('text','json','table'):
                old,encoding,bom=decode_text(path.read_bytes())
                value=args.get('text','')
                if not isinstance(value,str):raise ValueError('Text must be a string')
                if tool=='json':
                    parsed=json.loads(value)
                    value=json.dumps(parsed,ensure_ascii=False,indent=None if args.get('minify') else 2)
                if tool=='table':
                    rows=args.get('rows');delim=args.get('delimiter',',')
                    if delim not in (',','\t',';','|'):raise ValueError('Choose comma, tab, semicolon or pipe delimiter')
                    if not isinstance(rows,list) or len(rows)>2000 or any(not isinstance(r,list) or len(r)>100 for r in rows):raise ValueError('Invalid table dimensions')
                    s=io.StringIO(newline='');writer=csv.writer(s,delimiter=delim,lineterminator='\r\n' if '\r\n' in old else '\n')
                    writer.writerows([[str(c) for c in row] for row in rows]);value=s.getvalue()
                raw=bom+value.encode(encoding)
                if len(raw)>TEXT_LIMIT:raise ValueError('Edited text exceeds 4 MiB')
                output.write_bytes(raw);report=dict(encoding=encoding,bom_preserved=bool(bom),characters=len(value))
            elif tool=='zip':
                index=int(args.get('index',0));total=0
                with zipfile.ZipFile(path) as src:
                    infos=src.infolist()
                    if len(infos)>10000 or not 0<=index<len(infos):raise ValueError('Archive entry count or selection exceeds editing limits')
                    if any(i.flag_bits&1 for i in infos):raise ValueError('Encrypted ZIP editing requires a decryption provider; raw inspection remains available.')
                    target=infos[index]
                    if target.is_dir() or target.file_size>TEXT_LIMIT:raise ValueError('Select a text file up to 4 MiB')
                    old,encoding,bom=decode_text(src.read(target));replacement=bom+str(args.get('text','')).encode(encoding)
                    if len(replacement)>TEXT_LIMIT:raise ValueError('Replacement text exceeds 4 MiB')
                    with zipfile.ZipFile(output,'w') as dst:
                        dst.comment=src.comment
                        for i,info in enumerate(infos):
                            total+=info.file_size
                            if info.file_size>EDIT_LIMIT or total>128*1024**2:raise ValueError('Expanded archive exceeds editing limits')
                            dst.writestr(info,replacement if i==index else src.read(info))
                    report=dict(entry=target.filename,repacked=True,signatures_preserved=False)
            elif tool=='pdf':
                from pypdf import PdfWriter
                reader=load_pdf(path,args.get('password',''));pages=args.get('pages',list(range(1,len(reader.pages)+1)));rotate=int(args.get('rotate',0))
                if not isinstance(pages,list) or not pages or len(pages)>2000 or rotate not in (0,90,180,270):raise ValueError('Choose page numbers and a rotation of 0, 90, 180 or 270')
                writer=PdfWriter()
                for number in pages:
                    if not isinstance(number,int) or not 1<=number<=len(reader.pages):raise ValueError('Page number outside document')
                    page=writer.add_page(reader.pages[number-1])
                    if rotate:page.rotate(rotate)
                with output.open('wb') as f:writer.write(f)
                name=new_name(data['name'],'.pdf');report=dict(pages=pages,rotation=rotate,unencrypted_output=True,document_level_features_preserved=False)
            elif tool=='image':
                from PIL import Image,ImageOps
                with Image.open(path) as source:
                    source.seek(0);im=ImageOps.exif_transpose(source).copy()
                crop=args.get('crop')
                if crop:
                    if not isinstance(crop,list) or len(crop)!=4:raise ValueError('Crop requires left, top, right, bottom')
                    left,top,right,bottom=[int(x) for x in crop]
                    if not 0<=left<right<=im.width or not 0<=top<bottom<=im.height:raise ValueError('Crop rectangle is outside image')
                    im=im.crop((left,top,right,bottom))
                rotate=int(args.get('rotate',0))
                if rotate not in (0,90,180,270):raise ValueError('Choose a 90-degree rotation')
                if rotate:im=im.rotate(-rotate,expand=True)
                resize=args.get('resize')
                if resize:
                    width,height=[int(x) for x in resize]
                    if min(width,height)<1 or max(width,height)>16384 or width*height>40000000:raise ValueError('Resize exceeds preview limits')
                    im=im.resize((width,height),Image.Resampling.LANCZOS)
                im.save(output,format='PNG');name=new_name(data['name'],'.png');report=dict(width=im.width,height=im.height,format='PNG',first_frame_only=True)
            elif tool=='audio':
                start=float(args.get('start',0));duration=float(args.get('duration',30));gain=float(args.get('gain',0))
                if not all(math.isfinite(v) for v in (start,duration,gain)) or start<0 or not 0<duration<=600 or not -60<=gain<=24:raise ValueError('Choose nonnegative start, duration up to 600 seconds, gain from -60 to +24 dB')
                r=subprocess.run([shutil.which('ffmpeg'),'-v','error','-nostdin','-y','-protocol_whitelist','file,pipe','-ss',str(start),'-i',str(path),
                    '-t',str(duration),'-vn','-af',f'volume={gain}dB','-c:a','pcm_s16le','-f','wav',str(output)],capture_output=True,timeout=90)
                if r.returncode:raise ValueError('Audio export failed: '+r.stderr.decode(errors='replace')[-1000:])
                name=new_name(data['name'],'.wav');report=dict(start=start,duration=duration,gain_db=gain,format='Decoded PCM16 WAV')
        return output,name,report
    except Exception:
        output.unlink(missing_ok=True)
        raise
