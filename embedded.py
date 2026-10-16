"""Bounded signature scan with structural BMP checks and declared-length carving."""
import struct

SCAN_LIMIT=64*1024**2
CANDIDATE_LIMIT=512
BMP_HIT_LIMIT=65536
SIGNATURES=[(b'\x89PNG\r\n\x1a\n','PNG image'),(b'PK\x03\x04','ZIP entry'),
    (b'%PDF-','PDF document'),(b'\x7fELF','ELF binary'),(b'MDMP','Windows minidump'),
    (b'glTF','GLB model'),(b'RIFF','RIFF container'),(b'\xff\xd8\xff','JPEG candidate')]


def bmp_header(raw,offset=0,parent_size=None):
    """Return a plausible BMP header; this does not validate compressed pixels."""
    if offset<0 or offset+26>len(raw) or raw[offset:offset+2]!=b'BM':return None
    size,reserved1,reserved2,pixels,dib=struct.unpack_from('<IHHII',raw,offset+2)
    if reserved1 or reserved2 or dib not in (12,40,52,56,64,108,124):return None
    if size<14+dib or not 14+dib<=pixels<=size or offset+14+dib>len(raw):return None
    if dib==12:
        width,height,planes,bits=struct.unpack_from('<HHHH',raw,offset+18);compression=0
    else:
        width,height,planes,bits,compression=struct.unpack_from('<iiHHI',raw,offset+18)
    if width<=0 or not height or planes!=1 or compression not in (0,1,2,3,4,5,6,11,12,13):return None
    if bits not in (1,4,8,16,24,32) and not(bits==0 and compression in (4,5)):return None
    if compression==0:
        stride=((width*bits+31)//32)*4
        if pixels+stride*abs(height)>size:return None
    actual=len(raw) if parent_size is None else parent_size
    return dict(offset=offset,kind='BMP image',format='bmp',size=size,end=offset+size,width=width,height=abs(height),
        top_down=height<0,bits_per_pixel=bits,compression=compression,complete=offset+size<=actual,
        boundary='BMP header-declared length',validation='Plausible file/DIB headers; pixel decoding occurs on open')


def scan(path):
    with path.open('rb') as f:raw=f.read(SCAN_LIMIT)
    actual=path.stat().st_size;found=[];limited=False;budget=[128*1024**2,False]
    archives=[];pos=0
    for _ in range(CANDIDATE_LIMIT):
        pos=raw.find(b'PK\x05\x06',pos)
        if pos<0:break
        candidate=zip_object(raw,pos,budget)
        if candidate:archives.append(candidate);found.append(candidate)
        pos+=4
    else:limited=True
    archive_locals={n for archive in archives for n in archive['local_offsets']}
    for signature,kind in SIGNATURES:
        offset=0;count=0
        while count<CANDIDATE_LIMIT:
            offset=raw.find(signature,offset)
            if offset<0:break
            candidate=None
            if signature.startswith(b'\x89PNG'):candidate=png_object(raw,offset,budget)
            elif signature==b'RIFF':candidate=riff_object(raw,offset,actual,budget)
            if not (signature==b'PK\x03\x04' and offset in archive_locals):
                found.append(candidate or dict(offset=offset,kind=kind,validation='Signature only; exact boundary unavailable'))
            offset+=len(signature);count+=1
        if count==CANDIDATE_LIMIT:limited=True
    offset=0;hits=0
    while hits<BMP_HIT_LIMIT:
        offset=raw.find(b'BM',offset)
        if offset<0:break
        candidate=bmp_header(raw,offset,actual)
        if candidate:found.append(candidate)
        offset+=2;hits+=1
    if hits==BMP_HIT_LIMIT:limited=True
    found.sort(key=lambda r:r['offset']);limited=limited or len(found)>CANDIDATE_LIMIT or budget[1]
    identities=[];children=[]
    for candidate in found:
        candidate.pop('local_offsets',None)
        if candidate['offset']==0 and candidate.get('size')==actual and candidate.get('complete'):
            identities.append(dict(candidate,reason='Whole-object signature: this is the current object, not a child'))
        else:children.append(candidate)
    return dict(candidates=children[:CANDIDATE_LIMIT],current_object=identities,scanned=len(raw),limited=limited,
        note='First 64 MiB scanned; maximum 512 candidates. BMP/RIFF use declared lengths; PNG uses CRC-checked chunks through IEND; classic ZIP uses central/local records and EOCD. Other signatures remain candidates without exact boundaries. BMP checks stop after 65,536 hits; structural validation has a 128 MiB byte budget. Detection does not imply every payload can be decoded.')


def _consume(budget,count):
    if budget is not None:
        if count>budget[0]:budget[1]=True;return False
        budget[0]-=count
    return True


def png_object(raw,offset=0,budget=None):
    import zlib
    if raw[offset:offset+8]!=b'\x89PNG\r\n\x1a\n':return None
    pos=offset+8;idat=False;dimensions=None
    for index in range(10000):
        if pos+12>len(raw):return None
        size=int.from_bytes(raw[pos:pos+4],'big');kind=raw[pos+4:pos+8];end=pos+12+size
        if end>len(raw) or not all(65<=v<=90 or 97<=v<=122 for v in kind):return None
        if not _consume(budget,size+12):return None
        if zlib.crc32(memoryview(raw)[pos+4:end-4])&0xffffffff!=int.from_bytes(raw[end-4:end],'big'):return None
        if index==0:
            if kind!=b'IHDR' or size!=13:return None
            width,height,depth,color,compression,filtering,interlace=struct.unpack_from('>IIBBBBB',raw,pos+8)
            allowed={0:(1,2,4,8,16),2:(8,16),3:(1,2,4,8),4:(8,16),6:(8,16)}
            if not width or not height or depth not in allowed.get(color,()) or compression or filtering or interlace>1:return None
            dimensions=(width,height)
        elif kind==b'IHDR':return None
        if kind==b'IDAT':idat=True
        if kind==b'IEND':
            if size or not idat:return None
            return dict(offset=offset,kind='PNG image',format='png',size=end-offset,end=end,
                width=dimensions[0],height=dimensions[1],complete=True,boundary='PNG chunks through IEND',
                validation='Chunk bounds and CRCs checked; image decoding occurs on open')
        pos=end
    return None


def riff_object(raw,offset=0,parent_size=None,budget=None):
    if offset+12>len(raw) or raw[offset:offset+4]!=b'RIFF':return None
    size=struct.unpack_from('<I',raw,offset+4)[0]+8;end=offset+size;form=bytes(raw[offset+8:offset+12])
    if size<12 or form not in (b'WAVE',b'WEBP',b'AVI '):return None
    actual=len(raw) if parent_size is None else parent_size
    complete=end<=actual;formats={b'WAVE':('WAV audio','wav'),b'WEBP':('WebP image','webp'),b'AVI ':('AVI video','avi')}
    kind,fmt=formats[form]
    result=dict(offset=offset,kind=kind,format=fmt,size=size,end=end,complete=complete,
        boundary='RIFF header-declared length',validation='RIFF length header; full chunk checks require the bytes in the scan window')
    if end>len(raw):return result
    pos=offset+12;seen=set()
    for _ in range(10000):
        if pos==end:break
        if pos+8>end or not _consume(budget,8):return None
        tag=bytes(raw[pos:pos+4]);n=struct.unpack_from('<I',raw,pos+4)[0];nextpos=pos+8+n+(n&1)
        if nextpos>end:return None
        if tag==b'fmt ' and form==b'WAVE':
            if n<16:return None
            encoding,channels,rate,byte_rate,align,bits=struct.unpack_from('<HHIIHH',raw,pos+8)
            if not encoding or not channels or not rate or not align:return None
            result.update(channels=channels,sample_rate=rate,bits_per_sample=bits)
        seen.add(tag);pos=nextpos
    else:return None
    if form==b'WAVE' and not {b'fmt ',b'data'}<=seen:return None
    result['validation']='RIFF declared length and top-level chunk bounds checked; media decoding occurs on open'
    return result


def zip_object(raw,eocd,budget=None):
    """Validate classic single-disk ZIP records and infer base from EOCD offsets.

    No member decompression during scanning. ZIP64/spanned/relative-to-parent
    layouts remain signature candidates instead of guessing their boundaries.
    """
    if eocd+22>len(raw) or raw[eocd:eocd+4]!=b'PK\x05\x06':return None
    disk,cd_disk,n_disk,count,cd_size,cd_offset,comment=struct.unpack_from('<4H2IH',raw,eocd+4)
    if disk or cd_disk or n_disk!=count or count==65535 or count>10000 or cd_size==0xffffffff or cd_offset==0xffffffff:return None
    end=eocd+22+comment;cd=eocd-cd_size;start=cd-cd_offset
    if start<0 or cd<start or end>len(raw) or not _consume(budget,cd_size+22):return None
    pos=cd;locals=[]
    for _ in range(count):
        if pos+46>eocd or raw[pos:pos+4]!=b'PK\x01\x02':return None
        flags,method=struct.unpack_from('<HH',raw,pos+8)
        crc,compressed,size=struct.unpack_from('<III',raw,pos+16)
        names,extra,comments,diskno=struct.unpack_from('<4H',raw,pos+28)
        local=struct.unpack_from('<I',raw,pos+42)[0]+start
        name=raw[pos+46:pos+46+names];nextpos=pos+46+names+extra+comments
        if nextpos>eocd or diskno or compressed==0xffffffff or size==0xffffffff or local<start or local+30>cd:return None
        if raw[local:local+4]!=b'PK\x03\x04':return None
        localflags,localmethod=struct.unpack_from('<HH',raw,local+6)
        localnames,localextra=struct.unpack_from('<HH',raw,local+26)
        data=local+30+localnames+localextra
        if localflags!=flags or localmethod!=method or localnames!=names or data+compressed>cd:return None
        if raw[local+30:local+30+localnames]!=name:return None
        if not flags&8 and struct.unpack_from('<III',raw,local+14)!=(crc,compressed,size):return None
        locals.append(local);pos=nextpos
    if pos!=eocd or (count and min(locals)!=start) or (not count and (cd_size or cd_offset)):return None
    return dict(offset=start,kind='ZIP archive',format='zip',size=end-start,end=end,complete=True,
        entry_count=count,local_offsets=locals,boundary='ZIP local records, central directory and EOCD/comment',
        validation='Classic ZIP central/local bounds checked; member CRCs checked when extracting')


def primary_zip(path):
    """An embedded ZIP with a prefix is not the identity of its parent."""
    import zipfile
    with path.open('rb') as f:head=f.read(4)
    if head not in (b'PK\x03\x04',b'PK\x05\x06'):return False
    try:
        with zipfile.ZipFile(path) as z:
            entries=z.infolist()
            return min(e.header_offset for e in entries)==0 if entries else z.start_dir==0
    except (ValueError,OSError,zipfile.BadZipFile):return False


def object_at(raw,offset,fmt,parent_size=None):
    budget=[128*1024**2,False]
    if fmt=='bmp':return bmp_header(raw,offset,parent_size)
    if fmt=='png':return png_object(raw,offset,budget)
    if fmt in ('wav','webp','avi'):
        value=riff_object(raw,offset,parent_size,budget)
        return value if value and value['format']==fmt else None
    if fmt=='zip':
        pos=offset;hits=0
        while hits<CANDIDATE_LIMIT:
            pos=raw.find(b'PK\x05\x06',pos)
            if pos<0:return None
            value=zip_object(raw,pos,budget)
            if value and value['offset']==offset:return value
            pos+=4;hits+=1
    return None
