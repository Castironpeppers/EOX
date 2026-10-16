"""Disc filesystem browsing, cartridge headers and copy-only ROM/ISO changes."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import secrets
import shutil
import struct
import zipfile

ROM_EXTS={'.gb','.gbc','.gba','.nes','.sfc','.smc','.nds','.z64','.v64','.n64','.sms','.gg','.rom'}
DISC_EXTS={'.iso','.udf','.img','.bin','.cue','.chd','.cso','.mdf','.nrg'}
GB_LOGO=bytes.fromhex('CE ED 66 66 CC 0D 00 0B 03 73 00 83 00 0C 00 0D 00 08 11 1F 88 89 00 0E DC CC 6E E6 DD DD D9 99 BB BB 67 63 6E 0E EC CC DD DC 99 9F BB B9 33 3E')


def ascii_text(data):return data.split(b'\0',1)[0].decode('ascii','replace').strip()


GB_TYPES={0x00,0x01,0x02,0x03,0x05,0x06,0x08,0x09,0x0b,0x0c,0x0d,
          0x0f,0x10,0x11,0x12,0x13,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x20,0x22,0xfc,0xfd,0xfe,0xff}


def gb_detection(head,size):
    """Content-only evidence at the fixed GB header; score is not a probability.

    A missing logo requires checksum, exact size, plausible fields, a readable
    title AND a conventional entry jump. Filename and global checksum do not
    influence classification. A canonical logo retains legacy recognition.
    """
    if len(head)<0x150:return None
    code=head[0x148]
    declared=(32768<<code) if code<=8 else {0x52:72*16384,0x53:80*16384,0x54:96*16384}.get(code)
    checksum=(-sum(head[0x134:0x14d])-25)&255
    title=head[0x134:0x143 if head[0x143]&128 else 0x144].split(b'\0',1)[0].rstrip(b'\xff ')
    start=0x101 if head[0x100]==0 else 0x100
    entry=head[start]==0xc3 and 0x150<=int.from_bytes(head[start+1:start+3],'little')<0x8000
    checks=dict(logo_matches=head[0x104:0x134]==GB_LOGO,
        header_checksum_valid=head[0x14d]==checksum,
        declared_size_matches=declared is not None and size==declared,
        cartridge_fields_plausible=head[0x147] in GB_TYPES and head[0x149] in range(6)
            and head[0x143] in (0,0x80,0xc0) and head[0x146] in (0,3) and head[0x14a] in (0,1),
        readable_title=bool(title) and all(32<=v<=126 for v in title),
        conventional_entry_jump=entry)
    weights=dict(logo_matches=25,header_checksum_valid=25,declared_size_matches=20,
        cartridge_fields_plausible=10,readable_title=10,conventional_entry_jump=10)
    score=sum(weights[k] for k,v in checks.items() if v)
    accepted=checks['logo_matches'] or all(checks[k] for k in checks if k!='logo_matches')
    warnings=[]
    if accepted:
        if not checks['logo_matches']:warnings.append('Nintendo logo differs; identified as a GB/GBC structural candidate, not verified as bootable.')
        if not checks['header_checksum_valid']:warnings.append('GB header checksum is invalid.')
        if not checks['declared_size_matches']:warnings.append('GB declared ROM size does not match the file length.')
    return dict(platform='Game Boy / Game Boy Color',accepted=accepted,score=score,max_score=100,
        confidence='high' if score>=90 else 'structural candidate' if accepted else 'insufficient evidence',
        header_offset=0x100,checks=checks,declared_rom_bytes=declared,title=title.decode('ascii','replace'),
        warnings=warnings,note='Heuristic evidence score, not a probability or proof of an executable game. Noncanonical headers may require manual ROM tools.')


def mpeg_frame_header(head):
    """Reject reserved MPEG version/layer/bitrate/rate fields, including FF FF."""
    if len(head)<4 or head[0]!=255 or head[1]&0xe0!=0xe0:return False
    return ((head[1]>>3)&3)!=1 and ((head[1]>>1)&3)!=0 and ((head[2]>>4)&15)!=15 and ((head[2]>>2)&3)!=3


def rom_info(path,name):
    size=Path(path).stat().st_size
    with Path(path).open('rb') as f:head=f.read(min(size,512*1024))
    detection=gb_detection(head,size)
    ext=Path(name).suffix.lower();result=dict(platform='ROM image / raw candidate',size=size,extension=ext,
        note='Header checks and hashes help verify a dump; they do not prove every cartridge bank was read or that an emulator supports its mapper.')
    if head[:4]==b'NES\x1a' and len(head)>=16:
        nes2=head[7]&12==8;trainer=bool(head[6]&4)
        result.update(platform='NES',header_format='NES 2.0' if nes2 else 'iNES',mapper=(head[6]>>4)|(head[7]&0xf0)|((head[8]&15)<<8 if nes2 else 0),
            prg_rom_bytes=head[4]*16384,chr_rom_bytes=head[5]*8192,trainer=trainer,prg_offset=16+(512 if trainer else 0))
        if nes2:
            def rom_length(low,high,unit):return (1<<(low>>2))*((low&3)*2+1) if high==15 else ((high<<8)|low)*unit
            result['prg_rom_bytes']=rom_length(head[4],head[9]&15,16384);result['chr_rom_bytes']=rom_length(head[5],head[9]>>4,8192)
        result['declared_payload_fits']=result['prg_offset']+result['prg_rom_bytes']+result['chr_rom_bytes']<=size
    elif len(head)>=0x150 and (ext in ('.gb','.gbc') or (detection and detection['accepted'])):
        result['detection']=detection
        result['warnings']=detection['warnings']
        header_check=0
        for v in head[0x134:0x14d]:header_check=(header_check-v-1)&255
        digest=0
        with Path(path).open('rb') as f:
            while block:=f.read(1024**2):digest=(digest+sum(block))&65535
        digest=(digest-head[0x14e]-head[0x14f])&65535
        size_code=head[0x148];declared=(32768<<size_code) if size_code<=8 else {0x52:72*16384,0x53:80*16384,0x54:96*16384}.get(size_code)
        result.update(declared_rom_bytes=declared,declared_size_matches=(size==declared) if declared else None,platform='Game Boy / Game Boy Color',title=detection['title'],
            color_flag=hex(head[0x143]),cartridge_type=hex(head[0x147]),rom_size_code=hex(head[0x148]),ram_size_code=hex(head[0x149]),
            logo_matches=head[0x104:0x134]==GB_LOGO,header_checksum=dict(stored=head[0x14d],calculated=header_check,valid=head[0x14d]==header_check),
            global_checksum=dict(stored=int.from_bytes(head[0x14e:0x150],'big'),calculated=digest,valid=int.from_bytes(head[0x14e:0x150],'big')==digest))
    elif ext=='.gba' and len(head)>=0xc0:
        checksum=(-sum(head[0xa0:0xbd])-0x19)&255
        result.update(platform='Game Boy Advance',title=ascii_text(head[0xa0:0xac]),game_code=ascii_text(head[0xac:0xb0]),
            maker=ascii_text(head[0xb0:0xb2]),fixed_byte=hex(head[0xb2]),revision=head[0xbc],
            header_checksum=dict(stored=head[0xbd],calculated=checksum,valid=head[0xbd]==checksum))
    elif ext=='.nds' and len(head)>=0x160:
        result.update(platform='Nintendo DS',title=ascii_text(head[:12]),game_code=ascii_text(head[12:16]),
            arm9_offset=struct.unpack_from('<I',head,0x20)[0],arm9_size=struct.unpack_from('<I',head,0x2c)[0],
            arm7_offset=struct.unpack_from('<I',head,0x30)[0],arm7_size=struct.unpack_from('<I',head,0x3c)[0])
    elif head[:4] in (b'\x80\x37\x12\x40',b'\x37\x80\x40\x12',b'\x40\x12\x37\x80'):
        order={b'\x80\x37\x12\x40':'big endian (.z64)',b'\x37\x80\x40\x12':'16-bit swapped (.v64)',b'\x40\x12\x37\x80':'32-bit reversed (.n64)'}[head[:4]]
        canonical=head
        if head[:4]==b'\x37\x80\x40\x12':canonical=b''.join(head[i:i+2][::-1] for i in range(0,len(head),2))
        elif head[:4]==b'\x40\x12\x37\x80':canonical=b''.join(head[i:i+4][::-1] for i in range(0,len(head),4))
        result.update(platform='Nintendo 64',byte_order=order,title=ascii_text(canonical[0x20:0x34]),crc1=canonical[0x10:0x14].hex(),crc2=canonical[0x14:0x18].hex())
    elif ext in ('.sfc','.smc'):
        prefix=512 if size%1024==512 else 0;candidates=[]
        for off in (0x7fc0,0xffc0,0x40ffc0):
            off+=prefix
            if off+32<=len(head):
                complement,checksum=struct.unpack_from('<HH',head,off+28)
                title=head[off:off+21];score=sum(32<=b<=126 for b in title)+20*((complement^checksum)==65535)
                candidates.append((score,off,title,checksum,complement))
        if candidates:
            _,off,title,checksum,complement=max(candidates)
            result.update(platform='SNES (header candidate)',title=ascii_text(title),header_offset=off,copier_prefix_bytes=prefix,
                checksum=checksum,complement=complement,complement_pair_valid=checksum^complement==65535)
    return result


def disc_info(path):
    path=Path(path);size=path.stat().st_size;result=dict(filesystem='Disc image / raw sectors',entries=[],size=size,pycdlib=bool(importlib.util.find_spec('pycdlib')),
        note='Logical ISO filesystem view. Audio CD, mixed-mode tracks, boot data and encrypted Blu-ray content require their own formats/readers.')
    with path.open('rb') as f:
        primary=None;joliet=None
        for sector in range(16,80):
            f.seek(sector*2048);block=f.read(2048)
            if len(block)<2048:break
            if block[1:6]==b'CD001':
                if block[0]==1:primary=block
                elif block[0]==2 and block[88:91] in (b'%/@',b'%/C',b'%/E'):joliet=block
                elif block[0]==255:break
            elif block[1:6] in (b'NSR02',b'NSR03'):result['filesystem']='UDF disc image'
        selected=joliet or primary
        if selected:
            blocksize=struct.unpack_from('<H',selected,128)[0]
            if blocksize!=2048:raise ValueError('Disc block size needs an additional parser; raw sectors remain available')
            result.update(filesystem='ISO9660 / Joliet' if joliet else 'ISO9660',volume=ascii_text(primary[40:72] if primary else b''),
                logical_block_size=2048,declared_bytes=struct.unpack_from('<I',selected,80)[0]*2048)
            seen=set();root=selected[156:190]
            def walk(extent,length,parts,depth):
                if depth>32 or extent in seen or len(result['entries'])>=10000:return
                seen.add(extent)
                if length>16*1024**2 or extent*2048+length>size:raise ValueError('Directory range exceeds disc parse limits')
                f.seek(extent*2048);directory=f.read(length);p=0
                while p<len(directory):
                    n=directory[p]
                    if not n:p=((p//2048)+1)*2048;continue
                    if n<34 or p+n>len(directory):raise ValueError('Invalid ISO directory record')
                    record=directory[p:p+n];identifier=record[33:33+record[32]];p+=n
                    if identifier in (b'\0',b'\x01'):continue
                    name=identifier.decode('utf-16be' if joliet else 'ascii','replace');offset=struct.unpack_from('<I',record,2)[0]*2048
                    length=struct.unpack_from('<I',record,10)[0];flags=record[25];directory_flag=bool(flags&2)
                    entry=dict(index=len(result['entries']),path='/'+('/'.join(parts+[name])),name=name,offset=offset,size=length,directory=directory_flag,multi_extent=bool(flags&128) or bool(record[1] or record[26] or record[27]))
                    result['entries'].append(entry)
                    if directory_flag:walk(offset//2048,length,parts+[name],depth+1)
                    if len(result['entries'])>=10000:break
            walk(struct.unpack_from('<I',root,2)[0],struct.unpack_from('<I',root,10)[0],[],0)
            return result
    if result['filesystem']=='UDF disc image' and not result['pycdlib']:result['note']+=' Install optional pycdlib for UDF filesystem entries.'
    if result['pycdlib']:
        import pycdlib
        iso=pycdlib.PyCdlib()
        try:
            iso.open(str(path));namespace='udf_path' if iso.has_udf() else 'joliet_path' if iso.has_joliet() else 'rr_path' if iso.has_rock_ridge() else 'iso_path'
            result['filesystem']='UDF / '+namespace if iso.has_udf() else namespace
            for base,dirs,files in iso.walk(**{namespace:'/'}):
                for name in files:
                    full=base.rstrip('/')+'/'+name;record=iso.get_record(**{namespace:full})
                    result['entries'].append(dict(index=len(result['entries']),path=full,name=name,size=record.data_length,directory=False,namespace=namespace))
                    if len(result['entries'])>=10000:return result
        except Exception as e:result['note']+=' Provider note: '+str(e)
        finally:
            try:iso.close()
            except Exception:pass
    return result


def extract_disc(path,entry,output):
    if entry.get('directory') or entry.get('multi_extent'):raise ValueError('Select a single-extent file for native extraction')
    if entry.get('offset') is not None and entry['offset']+entry['size']>Path(path).stat().st_size:raise ValueError('Disc entry is truncated')
    if entry['size']>256*1024**2:raise ValueError('Entry extraction is limited to 256 MiB')
    if entry.get('namespace'):
        import pycdlib
        iso=pycdlib.PyCdlib()
        try:iso.open(str(path));iso.get_file_from_iso(str(output),**{entry['namespace']:entry['path']})
        finally:
            try:iso.close()
            except Exception:pass
    else:
        with Path(path).open('rb') as f,Path(output).open('wb') as out:
            f.seek(entry['offset']);remaining=entry['size']
            while remaining:
                data=f.read(min(1024**2,remaining))
                if not data:raise ValueError('Disc entry is truncated')
                out.write(data);remaining-=len(data)


def fix_rom(path,name,folder):
    if Path(path).stat().st_size>128*1024**2:raise ValueError('ROM checksum repair is limited to 128 MiB')
    data=bytearray(Path(path).read_bytes());info=rom_info(path,name)
    if info['platform']=='Game Boy / Game Boy Color':
        checksum=0
        for v in data[0x134:0x14d]:checksum=(checksum-v-1)&255
        data[0x14d]=checksum;value=(sum(data)-data[0x14e]-data[0x14f])&65535;data[0x14e:0x150]=value.to_bytes(2,'big')
    elif info['platform']=='Game Boy Advance':data[0xbd]=(-sum(data[0xa0:0xbd])-0x19)&255
    else:raise ValueError('Automatic checksum repair currently covers GB/GBC and GBA. Other ROMs keep byte-patching tools.')
    out=Path(folder)/(secrets.token_hex(16)+'.rom');out.write_bytes(data)
    p=Path(name);return out,p.stem+'-checksums-fixed'+p.suffix


def apply_ips(source,patch,folder):
    if Path(source).stat().st_size>128*1024**2:raise ValueError('IPS source limit is 128 MiB')
    data=bytearray(Path(source).read_bytes());patch=bytes(patch)
    if len(data)>128*1024**2 or len(patch)>16*1024**2 or patch[:5]!=b'PATCH':raise ValueError('Provide a classic IPS patch; source limit 128 MiB / patch limit 16 MiB')
    p=5;records=0
    while p+3<=len(patch) and patch[p:p+3]!=b'EOF':
        offset=int.from_bytes(patch[p:p+3],'big');p+=3
        if p+2>len(patch):raise ValueError('Truncated IPS record')
        length=int.from_bytes(patch[p:p+2],'big');p+=2
        if length:
            content=patch[p:p+length];p+=length
            if len(content)!=length:raise ValueError('Truncated IPS replacement')
        else:
            if p+3>len(patch):raise ValueError('Truncated IPS RLE record')
            count=int.from_bytes(patch[p:p+2],'big');content=bytes([patch[p+2]])*count;p+=3
        end=offset+len(content)
        if end>128*1024**2:raise ValueError('IPS result exceeds 128 MiB')
        if end>len(data):data.extend(b'\0'*(end-len(data)))
        data[offset:end]=content;records+=1
    if patch[p:p+3]!=b'EOF':raise ValueError('IPS end marker is missing')
    p+=3
    if len(patch)-p==3:
        length=int.from_bytes(patch[p:p+3],'big')
        if length<len(data):del data[length:]
        else:data.extend(b'\0'*(length-len(data)))
    elif len(patch)!=p:raise ValueError('Unexpected trailing IPS data')
    out=Path(folder)/(secrets.token_hex(16)+'.patched');out.write_bytes(data);return out,records


def replace_iso(path,entry,replacement,folder):
    if entry.get('directory') or entry.get('multi_extent'):raise ValueError('Select a single-extent file for replacement')
    if len(replacement)>64*1024**2:raise ValueError('Replacement is limited to 64 MiB')
    if entry.get('offset') is not None and entry['offset']+entry['size']>Path(path).stat().st_size:raise ValueError('Disc entry is truncated')
    if not entry.get('namespace') and len(replacement)==entry['size'] and not entry.get('multi_extent') and not entry.get('directory'):
        out=Path(folder)/(secrets.token_hex(16)+'.iso');shutil.copyfile(path,out)
        with out.open('r+b') as f:f.seek(entry['offset']);f.write(replacement)
        return out
    if not importlib.util.find_spec('pycdlib'):raise ValueError('Install optional pycdlib for ISO entry replacement; file extraction and raw editing remain available')
    if len(replacement)>64*1024**2:raise ValueError('Replacement is limited to 64 MiB')
    import pycdlib
    out=Path(folder)/(secrets.token_hex(16)+'.iso');shutil.copyfile(path,out)
    iso=pycdlib.PyCdlib();final=None
    try:
        iso.open(str(out));namespace=entry.get('namespace') or ('joliet_path' if iso.has_joliet() else 'iso_path')
        iso.modify_file_in_place(io.BytesIO(replacement),len(replacement),**{namespace:entry['path']})
        final=Path(folder)/(secrets.token_hex(16)+'.iso')
        iso.write(str(final));iso.close();out.unlink(missing_ok=True);return final
    except Exception as exc:
        try:iso.close()
        except Exception:pass
        out.unlink(missing_ok=True)
        if final:final.unlink(missing_ok=True)
        raise ValueError('ISO replacement: '+str(exc)) from exc
