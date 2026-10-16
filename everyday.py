"""Ordinary file tasks: media conversion, archive maintenance, document corrections."""
import difflib
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path,PurePosixPath
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import zipfile

MAX_MEMBER=256*1024**2
MAX_EXPANDED=1024**3

def present(name):return importlib.util.find_spec(name) is not None

def fresh_name(name,extension=None):
    p=Path(name);return p.stem+'-edited'+(extension or p.suffix)

def source_check(path,data,cancel=None):
    digest=hashlib.sha256()
    with Path(path).open('rb') as f:
        while block:=f.read(1024**2):
            if cancel and cancel.is_set():raise ValueError('Task canceled')
            digest.update(block)
    if digest.hexdigest()!=data['sha256']:raise ValueError('Source changed. Reopen it before editing.')

def archive_name(name):
    name=str(name).replace('\\','/')
    parts=PurePosixPath(name).parts
    if not name or name.startswith('/') or any(p in ('..','.') or ':' in p for p in parts) or '\0' in name:raise ValueError('Archive names must be relative paths without parent traversal or drive letters')
    return '/'.join(parts)

def sevenzip():
    found=shutil.which('7zz') or shutil.which('7z')
    if found:return found
    for env in ('ProgramFiles','ProgramFiles(x86)'):
        candidate=Path(os.environ.get(env,'C:/Program Files'))/'7-Zip'/'7z.exe'
        if candidate.is_file():return str(candidate)
    return None

def external_entries(path):
    command=sevenzip()
    if not command:raise ValueError('Install 7-Zip for RAR/7z contents; the file remains available as bytes')
    run=subprocess.run([command,'l','-slt','-ba','-sccUTF-8','--',str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
    if run.returncode:raise ValueError('Archive listing: '+run.stderr.decode(errors='replace')[-1000:])
    if len(run.stdout)>8*1024**2:raise ValueError('Archive listing is too large')
    entries=[]
    for part in run.stdout.decode(errors='replace').replace('\r\n','\n').split('\n\n'):
        fields=dict(line.split(' = ',1) for line in part.splitlines() if ' = ' in line)
        if 'Path' not in fields:continue
        entries.append(dict(index=len(entries),name=fields['Path'],size=int(fields.get('Size','0')),directory=fields.get('Folder')=='+' or fields.get('Attributes','').startswith('D'),encrypted=fields.get('Encrypted')=='+'))
        if len(entries)>10000:raise ValueError('Archive listing limit is 10,000 entries')
    return entries

def archive_entries(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:return [dict(index=i,name=e.filename,size=e.file_size,directory=e.is_dir(),encrypted=bool(e.flag_bits&1),link=(e.external_attr>>16)&0xf000==0xa000) for i,e in enumerate(z.infolist())]
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as t:return [dict(index=i,name=e.name,size=e.size,directory=e.isdir(),encrypted=False,link=not(e.isfile() or e.isdir())) for i,e in enumerate(t)]
    return external_entries(path)

def copy_member(src,dst,size_limit=MAX_MEMBER):
    count=0
    while block:=src.read(65536):
        count+=len(block)
        if count>size_limit:raise ValueError('Archive entry exceeds 256 MiB')
        dst.write(block)
    return count

def read_external(path,name,dest,size_limit=MAX_MEMBER):
    command=sevenzip()
    if not command:raise ValueError('Install 7-Zip to read this archive')
    with tempfile.TemporaryFile() as errors:
        process=subprocess.Popen([command,'x','-so','-spd','-y','--',str(path),name],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=errors)
        try:
            with Path(dest).open('wb') as out:copy_member(process.stdout,out,size_limit)
            process.wait(timeout=30)
            if process.returncode:raise ValueError('Archive member could not be read. Encrypted archives need a password-capable provider.')
        finally:
            if process.poll() is None:process.kill();process.wait()
            process.stdout.close()

def repack_archive(path,data,args,folder):
    fmt=args.get('format','zip')
    if fmt not in ('zip','tar','tar.gz','7z','rar'):raise ValueError('Choose ZIP, TAR, TAR.GZ, 7z or RAR')
    if fmt=='7z' and not sevenzip():raise ValueError('Install 7-Zip to write 7z archives')
    if fmt=='rar' and not shutil.which('rar'):raise ValueError('Install the RAR command-line writer, or choose ZIP / TAR / 7z')
    entries=archive_entries(path) if path else []
    remove=args.get('remove',[]);add=args.get('add',[])
    if not isinstance(remove,list) or any(type(i)!=int or i<0 or i>=len(entries) for i in remove):raise ValueError('Invalid archive removal selection')
    if not isinstance(add,list) or len(entries)+len(add)>10000:raise ValueError('Archive entry limit is 10,000')
    removed=set(remove);out=Path(folder)/(secrets.token_hex(16)+'.'+fmt);total=0
    with tempfile.TemporaryDirectory(prefix='eox-repack-',dir=folder) as work:
        stage=Path(work);names=set();metadata={}
        for e in entries:
            if e['index'] in removed:continue
            name=archive_name(e['name']);key=name.rstrip('/').casefold()
            if key in names:raise ValueError('Duplicate archive names: remove a duplicate before repacking')
            names.add(key);target=stage/name
            if e.get('encrypted') or e.get('link'):raise ValueError('Remove encrypted/link/special entries before repacking this archive')
            if e['directory']:target.mkdir(parents=True,exist_ok=True);continue
            if e['size']>MAX_MEMBER:raise ValueError('Archive member limit is 256 MiB')
            total+=e['size']
            if total>MAX_EXPANDED:raise ValueError('Archive expanded-size limit is 1 GiB')
            target.parent.mkdir(parents=True,exist_ok=True)
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as z:
                    info=z.infolist()[e['index']];metadata[name]=info
                    with z.open(info) as src,target.open('wb') as dst:copy_member(src,dst)
            elif tarfile.is_tarfile(path):
                with tarfile.open(path) as t:
                    info=t.getmembers()[e['index']];metadata[name]=info
                    with t.extractfile(info) as src,target.open('wb') as dst:copy_member(src,dst)
            else:read_external(path,e['name'],target)
        for item in add:
            source=Path(item['path']);name=archive_name(item['name']);key=name.casefold()
            if key in names:raise ValueError('Added file name already exists. Remove it first or choose another name.')
            names.add(key);size=source.stat().st_size;total+=size
            if size>MAX_MEMBER or total>MAX_EXPANDED:raise ValueError('Archive size limit exceeded: 256 MiB per member / 1 GiB total')
            target=stage/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        try:
            if fmt=='zip':
                with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
                    if path and zipfile.is_zipfile(path):
                        with zipfile.ZipFile(path) as original:z.comment=original.comment
                    for p in sorted(stage.rglob('*')):
                        name=p.relative_to(stage).as_posix()
                        if p.is_dir():z.writestr(name+'/',b'');continue
                        info=metadata.get(name)
                        if isinstance(info,zipfile.ZipInfo):
                            with p.open('rb') as src,z.open(info,'w') as dst:shutil.copyfileobj(src,dst)
                        else:z.write(p,name)
            elif fmt in ('tar','tar.gz'):
                with tarfile.open(out,'w:gz' if fmt=='tar.gz' else 'w') as t:
                    for p in sorted(stage.rglob('*')):
                        name=p.relative_to(stage).as_posix();info=metadata.get(name)
                        if isinstance(info,tarfile.TarInfo) and p.is_file():
                            with p.open('rb') as f:t.addfile(info,f)
                        else:t.add(p,arcname=name,recursive=False)
            else:
                if not any(stage.iterdir()):raise ValueError('Add at least one file for a 7z/RAR archive')
                cmd=[sevenzip(),'a','-t7z','-y',str(out),'.'] if fmt=='7z' else [shutil.which('rar'),'a','-r','-ep1','-idq','-y',str(out),'.']
                run=subprocess.run(cmd,cwd=stage,capture_output=True,timeout=120)
                if run.returncode:raise ValueError('Archive writer: '+run.stderr.decode(errors='replace')[-1000:])
            name=data.get('name','archive') if data else 'archive'
            stem=re.sub(r'\.(tar\.gz|tgz|zip|tar|7z|rar)$','',name,flags=re.I)
            return out,stem+'-edited.'+fmt,dict(removed=len(removed),added=len(add),format=fmt,expanded_bytes=total)
        except Exception:out.unlink(missing_ok=True);raise

W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
NS={'w':W}

def docx_parts(path):
    if not present('lxml'):raise ValueError('Install lxml for DOCX paragraph editing')
    from lxml import etree
    result={}
    with zipfile.ZipFile(path) as z:
        if sum(i.file_size for i in z.infolist())>128*1024**2:raise ValueError('Expanded DOCX exceeds 128 MiB')
        for name in z.namelist():
            if re.fullmatch(r'word/(document|header\d+|footer\d+)\.xml',name):
                raw=z.read(name)
                result[name]=etree.fromstring(raw,etree.XMLParser(resolve_entities=False,no_network=True))
    return result

def paragraph_nodes(p):return p.findall('.//w:t',NS)

def plain_paragraph(p):
    blocked=('hyperlink','fldChar','instrText','ins','del','sdt','tab','br','oMath')
    return not any(p.findall('.//w:'+tag,NS) for tag in blocked)

def describe_docx(path):
    parts=docx_parts(path);paragraphs=[]
    for part,root in parts.items():
        for i,p in enumerate(root.findall('.//w:p',NS)):
            text=''.join(n.text or '' for n in paragraph_nodes(p));style=p.find('w:pPr/w:pStyle',NS)
            paragraphs.append(dict(part=part,index=i,text=text,style=style.get('{'+W+'}val','Normal') if style is not None else 'Normal',editable=bool(paragraph_nodes(p)) and plain_paragraph(p)))
            if len(paragraphs)>=2000:return dict(paragraphs=paragraphs,limited=True)
    return dict(paragraphs=paragraphs,limited=False)

def patch_text_nodes(nodes,new):
    old=''.join(n.text or '' for n in nodes);bounds=[];position=0
    for node in nodes:
        length=len(node.text or '');bounds.append((node,position,position+length));position+=length
    for tag,a,b,c,d in reversed(difflib.SequenceMatcher(None,old,new,autojunk=False).get_opcodes()):
        if tag=='equal':continue
        targets=[(node,s,e) for node,s,e in bounds if s<b and e>a]
        if not targets:
            targets=[next(((node,s,e) for node,s,e in bounds if s<=a<e),bounds[-1])]
        for j,(node,s,e) in enumerate(targets):
            left=max(0,a-s);right=max(left,min(e,b)-s)
            node.text=(node.text or '')[:left]+(new[c:d] if j==0 else '')+(node.text or '')[right:]
            node.set('{http://www.w3.org/XML/1998/namespace}space','preserve')

def edit_docx(path,data,args,folder):
    from lxml import etree
    parts=docx_parts(path);part=args.get('part','word/document.xml');index=int(args.get('index',0));text=args.get('text','')
    if part not in parts or not isinstance(text,str) or len(text)>100000:raise ValueError('Invalid paragraph selection or text length')
    paragraphs=parts[part].findall('.//w:p',NS)
    if not 0<=index<len(paragraphs):raise ValueError('Paragraph not found')
    p=paragraphs[index];nodes=paragraph_nodes(p)
    if not nodes or not plain_paragraph(p):raise ValueError('Choose a plain-text paragraph; fields, tracked changes and special controls remain intact')
    patch_text_nodes(nodes,text)
    out=Path(folder)/(secrets.token_hex(16)+'.docx')
    try:
        with zipfile.ZipFile(path) as src,zipfile.ZipFile(out,'w') as dst:
            dst.comment=src.comment
            for info in src.infolist():
                if info.flag_bits&1:raise ValueError('Encrypted DOCX packages need to be decrypted first')
                dst.writestr(info,etree.tostring(parts[part],xml_declaration=True,encoding='UTF-8',standalone=True) if info.filename==part else src.read(info))
        return out,fresh_name(data['name'],'.docx'),dict(part=part,paragraph=index,run_styles_preserved=True,untouched_package_parts_preserved=True)
    except Exception:out.unlink(missing_ok=True);raise

def pdf_open(path,password=''):
    if not present('pymupdf'):raise ValueError('Install PyMuPDF for PDF text corrections')
    import pymupdf
    doc=pymupdf.open(path)
    if doc.needs_pass and not doc.authenticate(str(password)):doc.close();raise ValueError('Enter the PDF password')
    return doc

def pdf_words(page):
    spans=[]
    for block in page.get_text('dict')['blocks']:
        for line in block.get('lines',[]):
            for span in line.get('spans',[]):spans.append(dict(span,direction=line.get('dir',(1,0))))
    words=[]
    import pymupdf
    for i,w in enumerate(page.get_text('words')):
        rect=pymupdf.Rect(w[:4]);center=rect.tl+(rect.br-rect.tl)*.5
        candidates=[s for s in spans if pymupdf.Rect(s['bbox']).contains(center)]
        span=max(candidates,key=lambda s:(pymupdf.Rect(s['bbox'])&rect).get_area()) if candidates else None
        words.append(dict(index=i,text=w[4],bbox=list(rect),display_bbox=list(rect*page.rotation_matrix),block=w[5],line=w[6],word=w[7],style=span,editable=bool(span) and tuple(span['direction'])==(1.0,0.0)))
    return words

def describe_pdf(path,args):
    import base64,pymupdf
    with pdf_open(path,args.get('password','')) as doc:
        number=int(args.get('page',1))
        if not 1<=number<=len(doc):raise ValueError('Page number outside PDF')
        page=doc[number-1];scale=min(1.5,1400/max(page.rect.width,page.rect.height));pix=page.get_pixmap(matrix=pymupdf.Matrix(scale,scale),alpha=False)
        return dict(pages=len(doc),page=number,width=page.rect.width,height=page.rect.height,words=pdf_words(page),image='data:image/png;base64,'+base64.b64encode(pix.tobytes('png')).decode())

def edit_pdf_word(path,data,args,folder):
    import pymupdf
    number=int(args.get('page',1));index=int(args.get('word',-1));text=args.get('text','')
    if not isinstance(text,str) or len(text)>256 or any(c in text for c in '\r\n\0'):raise ValueError('Use a short, single-line replacement')
    out=Path(folder)/(secrets.token_hex(16)+'.pdf')
    with pdf_open(path,args.get('password','')) as doc:
        if not 1<=number<=len(doc):raise ValueError('Page number outside PDF')
        page=doc[number-1];words=pdf_words(page)
        if not 0<=index<len(words) or not words[index]['editable']:raise ValueError('Choose an editable horizontal word')
        if any(a.type[0]==pymupdf.PDF_ANNOT_REDACT for a in (page.annots() or [])):raise ValueError('This page has pending redactions. Finish those before correcting text.')
        word=words[index];style=word['style'];rect=pymupdf.Rect(word['bbox']);fontsize=style['size'];fontname='helv';matched=False;font=None
        for item in page.get_fonts(full=True):
            base=re.sub(r'^[A-Z]{6}\+','',item[3]).replace(' ','').lower()
            if base==style['font'].replace(' ','').lower():
                try:
                    buffer=doc.extract_font(item[0])[3]
                    if buffer:
                        candidate=pymupdf.Font(fontbuffer=buffer)
                        if all(candidate.has_glyph(ord(c)) for c in text):font=candidate;page.insert_font(fontname='EOXEdit',fontbuffer=buffer);fontname='EOXEdit';matched=True;break
                except Exception:pass
        if font is None:
            family=style['font'].lower();bold=bool(style['flags']&16);italic=bool(style['flags']&2)
            fontname=('tibi' if bold and italic else 'tibo' if bold else 'tiit' if italic else 'tiro') if 'times' in family else ('cobi' if bold and italic else 'cobo' if bold else 'coit' if italic else 'cour') if 'cour' in family else ('hebi' if bold and italic else 'hebo' if bold else 'heit' if italic else 'helv')
            font=pymupdf.Font(fontname)
            if not all(font.has_glyph(ord(c)) for c in text):raise ValueError('The available font lacks a replacement character')
        following=[w['bbox'][0] for w in words if w['block']==word['block'] and w['line']==word['line'] and w['bbox'][0]>=rect.x1 and w['index']!=index]
        available=max(rect.width,(min(following)-rect.x0-1) if following else page.cropbox.width-rect.x0-2)
        width=font.text_length(text,fontsize=fontsize)
        if width>available:
            size=fontsize*available/width
            if not args.get('fit',True) or size<fontsize*.8 or size<5:raise ValueError('Replacement is too wide for this word position. Use shorter text or edit the source document.')
            fontsize=size
        baseline=style['origin'][1];color=tuple(((style['color']>>shift)&255)/255 for shift in (16,8,0))
        page.add_redact_annot(rect,fill=False,cross_out=False);page.apply_redactions(images=0,graphics=0,text=0)
        if text:page.insert_text((rect.x0,baseline),text,fontname=fontname,fontsize=fontsize,color=color)
        try:doc.save(out,garbage=4,deflate=True)
        except Exception:out.unlink(missing_ok=True);raise
    return out,fresh_name(data['name'],'.pdf'),dict(page=number,original=word['text'],replacement=text,font_matched=matched,font=fontname,font_size=fontsize,method='Remove selected text and insert replacement; preserve images/graphics',unencrypted_output=True)

def image_export(path,data,args,folder):
    from PIL import Image,ImageOps
    fmt=str(args.get('format','png')).lower();formats={'png':'PNG','jpg':'JPEG','webp':'WEBP','bmp':'BMP','tiff':'TIFF'}
    if fmt not in formats:raise ValueError('Choose PNG, JPG, WebP, BMP or TIFF')
    quality=int(args.get('quality',90))
    if not 1<=quality<=100:raise ValueError('Quality must be 1–100')
    with Image.open(path) as original:
        original.seek(0);im=ImageOps.exif_transpose(original).copy()
    rotate=int(args.get('rotate',0))
    if rotate not in (0,90,180,270):raise ValueError('Choose 0, 90, 180 or 270 degrees')
    if rotate:im=im.rotate(-rotate,expand=True)
    if args.get('resize'):
        w,h=map(int,args['resize'])
        if min(w,h)<1 or max(w,h)>16384 or w*h>40000000:raise ValueError('Image resize exceeds limits')
        im=im.resize((w,h),Image.Resampling.LANCZOS)
    if im.mode=='P':im=im.convert('RGBA' if 'transparency' in im.info else 'RGB')
    if fmt=='webp' and im.mode not in ('RGB','RGBA','L','LA'):im=im.convert('RGB')
    if fmt in ('jpg','bmp') and im.mode not in ('RGB','L'):
        base=Image.new('RGB',im.size,'white')
        if 'A' in im.getbands():base.paste(im,mask=im.getchannel('A'))
        else:base.paste(im.convert('RGB'))
        im=base
    clean=Image.frombytes(im.mode,im.size,im.tobytes())
    if im.mode=='P':clean.putpalette(im.getpalette())
    out=Path(folder)/(secrets.token_hex(16)+'.'+fmt)
    try:clean.save(out,format=formats[fmt],quality=quality)
    except Exception:out.unlink(missing_ok=True);raise
    return out,fresh_name(data['name'],'.'+fmt),dict(format=fmt,width=im.width,height=im.height,metadata_stripped=True,first_frame_only=True)

AUDIO={'wav':('pcm_s16le','wav'),'mp3':('libmp3lame','mp3'),'flac':('flac','flac'),'ogg':('libvorbis','ogg'),'m4a':('aac','ipod')}
VIDEO={'mp4':('libx264','aac','mp4'),'webm':('libvpx-vp9','libopus','webm')}
IMAGE={'png','jpg','webp','bmp','tiff'}

def convert_file(path,data,args,folder,cancel,update):
    source_check(path,data,cancel);fmt=str(args.get('format','wav')).lower()
    if fmt in IMAGE:return image_export(path,data,args,folder)
    if fmt not in AUDIO and fmt not in VIDEO:raise ValueError('Choose a supported audio, video or image export format')
    ffmpeg=shutil.which('ffmpeg')
    if not ffmpeg:raise ValueError('Install FFmpeg for audio/video conversion')
    start=float(args.get('start',0));gain=float(args.get('gain',0));duration=args.get('duration');rate=args.get('rate');channels=args.get('channels');bitrate=int(args.get('bitrate',192));bits=int(args.get('bits',16))
    if not all(math.isfinite(v) for v in (start,gain)) or start<0 or not -60<=gain<=24 or not 32<=bitrate<=512:raise ValueError('Invalid start, gain or bitrate')
    if duration not in (None,''):
        duration=float(duration)
        if not math.isfinite(duration) or duration<=0:raise ValueError('Duration must be positive or blank for the rest of the file')
    else:duration=None
    if rate not in (None,'') and int(rate) not in (8000,16000,22050,32000,44100,48000,88200,96000,192000):raise ValueError('Choose a listed sample rate')
    if channels not in (None,'') and int(channels) not in (1,2):raise ValueError('Choose original, mono or stereo')
    if bits not in (16,24,32):raise ValueError('Choose 16, 24 or 32-bit WAV')
    out=Path(folder)/(secrets.token_hex(16)+'.'+fmt);progress=Path(folder)/(secrets.token_hex(16)+'.progress')
    cmd=[ffmpeg,'-v','error','-nostdin','-y','-protocol_whitelist','file,pipe','-ss',str(start),'-i',str(path)]
    if duration is not None:cmd+=['-t',str(duration)]
    if fmt in AUDIO:
        codec,mux=AUDIO[fmt];codec={16:'pcm_s16le',24:'pcm_s24le',32:'pcm_s32le'}[bits] if fmt=='wav' else codec
        cmd+=['-vn','-map','0:a:0','-c:a',codec]
    else:
        vcodec,codec,mux=VIDEO[fmt];cmd+=['-map','0:v:0','-map','0:a:0?','-c:v',vcodec,'-c:a',codec]
        cmd+=['-preset','veryfast','-crf','23','-pix_fmt','yuv420p','-vf','pad=ceil(iw/2)*2:ceil(ih/2)*2'] if fmt=='mp4' else ['-deadline','good','-cpu-used','4','-crf','32','-b:v','0']
    if gain:cmd+=['-af',f'volume={gain}dB']
    if rate not in (None,''):cmd+=['-ar',str(int(rate))]
    if channels not in (None,''):cmd+=['-ac',str(int(channels))]
    if fmt in ('mp3','m4a'):cmd+=['-b:a',str(bitrate)+'k']
    if fmt=='ogg':cmd+=['-q:a','5']
    if fmt=='mp4':cmd+=['-movflags','+faststart']
    cmd+=['-progress',str(progress),'-f',mux,str(out)]
    try:
        with tempfile.TemporaryFile() as errors:
            if cancel.is_set():raise ValueError('Task canceled')
            process=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=errors);cancel.eox_process=process
            try:
                while process.poll() is None:
                    if cancel.wait(.2):raise ValueError('Task canceled')
                    if progress.exists():
                        with progress.open('rb') as f:f.seek(max(0,progress.stat().st_size-4096));raw=f.read().decode(errors='replace')
                        matches=re.findall(r'out_time_us=(\d+)',raw)
                        if matches:update(float(matches[-1])/1000000)
                if process.returncode:errors.seek(0,2);length=errors.tell();errors.seek(max(0,length-2000));raise ValueError('Conversion: '+errors.read().decode(errors='replace'))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=3)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                cancel.eox_process=None
        return out,fresh_name(data['name'],'.'+fmt),dict(format=fmt,start=start,duration=duration,full_remainder=duration is None,gain_db=gain)
    except Exception:out.unlink(missing_ok=True);raise
    finally:progress.unlink(missing_ok=True)

class TaskJobs:
    def __init__(self,folder,register):self.folder=Path(folder);self.register=register;self.jobs={};self.lock=threading.Lock()
    def start(self,items,args):
        if not items or len(items)>200:raise ValueError('Choose 1–200 files for a batch')
        with self.lock:
            if any(j['state'] in ('running','packing') for j in self.jobs.values()):raise ValueError('A conversion batch is running. Finish or cancel it first.')
            ident=secrets.token_urlsafe(18);job=dict(id=ident,state='running',total=len(items),done=0,current='',seconds=0,results=[],errors=[],paths={},thread=None,cancel=threading.Event(),bundle=None)
            self.jobs[ident]=job;thread=threading.Thread(target=self._run,args=(job,items,dict(args)),daemon=True);job['thread']=thread;thread.start();return self.status(ident)
    def _run(self,job,items,args):
        for item in items:
            if job['cancel'].is_set():break
            job.update(current=item['data']['name'],seconds=0)
            try:
                out,name,report=convert_file(item['path'],item['data'],args,self.folder,job['cancel'],lambda seconds:job.update(seconds=seconds))
                if job['cancel'].is_set():out.unlink(missing_ok=True);break
                result=self.register(out,name);result['edit_report']=report;job['results'].append(result);job['paths'][result['id']]=out
            except Exception as e:job['errors'].append(dict(name=item['data']['name'],error=str(e)))
            job['done']+=1
        job['state']='packing'
        if job['results']:
            bundle=self.folder/(job['id']+'.zip');names=set()
            try:
                with zipfile.ZipFile(bundle,'w',zipfile.ZIP_DEFLATED) as z:
                    for result in job['results']:
                        # The registered output path is retained alongside its metadata.
                        source=job['paths'].get(result['id'])
                        if source is None:continue
                        stem=Path(result['name']).stem;suffix=Path(result['name']).suffix;name=Path(result['name']).name;count=2
                        while name.casefold() in names:name=f'{stem}-{count}{suffix}';count+=1
                        names.add(name.casefold());z.write(source,name)
                job['bundle']=str(bundle)
            except Exception as e:bundle.unlink(missing_ok=True);job['errors'].append(dict(name='Batch ZIP',error=str(e)))
        job['state']='canceled' if job['cancel'].is_set() else 'complete'
    def status(self,ident):
        if ident not in self.jobs:raise ValueError('Task job not found')
        return {k:v for k,v in self.jobs[ident].items() if k not in ('cancel','bundle','paths','thread')} | {'download':bool(self.jobs[ident]['bundle'])}
    def cancel(self,ident):
        if ident not in self.jobs:raise ValueError('Task job not found')
        self.jobs[ident]['cancel'].set();return self.status(ident)
    def download(self,ident):
        if ident not in self.jobs or not self.jobs[ident]['bundle']:raise ValueError('Batch ZIP is not ready')
        return Path(self.jobs[ident]['bundle'])
    def close(self):
        for j in self.jobs.values():
            j['cancel'].set();process=getattr(j['cancel'],'eox_process',None)
            if process and process.poll() is None:process.terminate()
        for j in self.jobs.values():
            if j['thread'] and j['thread'].is_alive():j['thread'].join(timeout=5)
