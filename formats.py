"""Bounded readable views for meshes and Windows crash artifacts."""
import base64
import csv
import io
import json
import math
import re
import struct

MESH_LIMIT = 150000
BUGCHECKS = {
    0xA:'IRQL_NOT_LESS_OR_EQUAL', 0x1A:'MEMORY_MANAGEMENT', 0x1E:'KMODE_EXCEPTION_NOT_HANDLED',
    0x3B:'SYSTEM_SERVICE_EXCEPTION', 0x50:'PAGE_FAULT_IN_NONPAGED_AREA',
    0x7B:'INACCESSIBLE_BOOT_DEVICE', 0x7E:'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED',
    0x9F:'DRIVER_POWER_STATE_FAILURE', 0xD1:'DRIVER_IRQL_NOT_LESS_OR_EQUAL',
    0xEF:'CRITICAL_PROCESS_DIED', 0x116:'VIDEO_TDR_FAILURE', 0x119:'VIDEO_SCHEDULER_INTERNAL_ERROR',
    0x124:'WHEA_UNCORRECTABLE_ERROR', 0x133:'DPC_WATCHDOG_VIOLATION',
    0x139:'KERNEL_SECURITY_CHECK_FAILURE', 0x154:'UNEXPECTED_STORE_EXCEPTION',
}


def crash_structure(b):
    def u(fmt, off):
        if off < 0 or off+struct.calcsize(fmt)>len(b):
            raise ValueError('Crash structure points outside file')
        return struct.unpack_from(fmt,b,off)
    if b[:4] == b'PAGE':
        is64=b[4:8] == b'DU64'
        if b[4:8] not in (b'DU64',b'DUMP'):
            raise ValueError('Unknown kernel dump variant')
        major, minor=u('<II',8)
        machine, cpus, code=u('<III',48 if is64 else 32)
        params=u('<QQQQ' if is64 else '<IIII',64 if is64 else 44)
        return dict(type='Windows kernel crash dump', bits=64 if is64 else 32,
            os_version=dict(major=major,build=minor), machine=hex(machine), processors=cpus,
            bugcheck=dict(code=f'0x{code:08X}',name=BUGCHECKS.get(code,'Unknown / consult Microsoft bugcheck reference'),
                          parameters=[hex(p) for p in params]),
            note='Header facts only. A stop code does not establish the culprit. Symbolized stacks require WinDbg.',
            streams=[],modules=[],threads=[])
    if b[:4] != b'MDMP':
        raise ValueError('Windows dump signature not recognized; raw bytes available')
    _, version, count, directory, checksum, timestamp, flags=u('<IIIIIIQ',0)
    if count>4096:
        raise ValueError('Unreasonable minidump stream count')
    types={3:'Threads',4:'Modules',5:'Memory ranges',6:'Exception',7:'System information',
           9:'Memory64 ranges',10:'Comment (ASCII)',11:'Comment (Unicode)',12:'Handles',
           14:'Unloaded modules',15:'Miscellaneous information',16:'Memory information',17:'Thread information'}
    result=dict(type='Windows minidump',version=hex(version),timestamp=timestamp,flags=hex(flags),
                streams=[],modules=[],threads=[],warnings=[],
                note='Stored facts only. An exception module is not proof of root cause; no symbolized stack analysis.')
    def string(off):
        n=u('<I',off)[0]
        if n>65536 or off+4+n>len(b):
            raise ValueError('Invalid minidump string')
        return bytes(b[off+4:off+4+n]).decode('utf-16le','replace')
    for i in range(count):
        kind,size,off=u('<III',directory+i*12)
        entry=dict(type=kind,name=types.get(kind,'Unknown stream'),offset=off,size=size)
        result['streams'].append(entry)
        if off+size>len(b):
            result['warnings'].append('Truncated '+entry['name'])
            continue
        try:
            def streamu(fmt, at):
                if at<off or at+struct.calcsize(fmt)>off+size:
                    raise ValueError('Field outside stream')
                return u(fmt,at)
            if kind==4:
                n=streamu('<I',off)[0]
                for j in range(min(n,10000)):
                    p=off+4+j*108
                    base,length,check,stamp,name=streamu('<QIIII',p)
                    streamu('<84s',p+24)
                    result['modules'].append(dict(name=string(name),base=hex(base),size=length,timestamp=stamp))
            elif kind==3:
                n=streamu('<I',off)[0]
                for j in range(min(n,10000)):
                    p=off+4+j*48
                    tid,suspend,priorityclass,priority,teb,stack,length,rva,contextlen,contextrva=streamu('<IIIIQQIIII',p)
                    result['threads'].append(dict(id=tid,priority=priority,teb=hex(teb),stack_address=hex(stack),
                        stack_bytes=length,stack_offset=rva,context_bytes=contextlen,context_offset=contextrva))
            elif kind==6:
                tid=streamu('<I',off)[0]
                code,flags,record,address,n,_=streamu('<IIQQII',off+8)
                params=streamu('<15Q',off+40)
                result['exception']=dict(thread_id=tid,code=f'0x{code:08X}',address=hex(address),
                                        parameters=[hex(v) for v in params[:min(n,15)]])
            elif kind==7:
                arch,level,rev,cpus,product,major,minor,build,platform,csd=streamu('<HHHBBIIIII',off)
                result['system']=dict(architecture={0:'x86',9:'x64',12:'ARM64'}.get(arch,str(arch)),
                    processors=cpus,major=major,minor=minor,build=build,service_pack=string(csd) if csd else '')
            elif kind in (10,11):
                result.setdefault('comments',[]).append(bytes(b[off:off+min(size,65536)]).decode('utf-16le' if kind==11 else 'utf-8','replace').rstrip('\0'))
        except (ValueError,struct.error) as e:
            result['warnings'].append(entry['name']+': '+str(e))
    if 'exception' in result:
        address=int(result['exception']['address'],16)
        result['exception']['containing_module']=next((m['name'] for m in result['modules']
            if int(m['base'],16)<=address<int(m['base'],16)+m['size']),None)
    return result


def structured_text(raw, name):
    text=raw.decode('utf-16' if raw[:2] in (b'\xff\xfe',b'\xfe\xff') else 'utf-8-sig','replace')
    ext=name.lower().rsplit('.',1)[-1]
    if ext in ('json','gltf','ipynb') or text.lstrip().startswith(('{','[')):
        try:
            return dict(type='JSON',pretty=json.dumps(json.loads(text),indent=2,ensure_ascii=False))
        except ValueError:
            return None
    if ext in ('csv','tsv'):
        try:
            delimiter='\t' if ext=='tsv' else csv.Sniffer().sniff(text[:8192]).delimiter
            rows=[]
            for i,row in enumerate(csv.reader(io.StringIO(text),delimiter=delimiter)):
                if i>=2000:
                    break
                rows.append(row[:100])
            return dict(type='Delimited table',rows=rows,note='First 2,000 rows / 100 columns.')
        except csv.Error:
            return None
    if ext in ('wer','log','txt'):
        fields=[]
        for line in text.splitlines()[:10000]:
            if '=' in line:
                key,value=line.split('=',1)
                if len(key)<100:
                    fields.append(dict(key=key,value=value))
        codes=re.findall(r'(?:BugCheck(?:Code)?|BUGCHECK_CODE|Stop(?:\s+code)?)\s*[:= ]\s*(0x[0-9a-f]+|[0-9a-f]{1,8})',text,re.I)
        if fields or codes:
            return dict(type='Log / Windows Error Reporting fields',fields=fields[:2000],
                        bugcheck_candidates=codes[:20],note='Extracted text fields; unlabelled numbers are not assumed to be stop codes.')
    return None


def mesh_data(path, name):
    if path.stat().st_size>64*1024**2:
        raise ValueError('3D parsing limited to 64 MiB in this build; use raw view for larger files')
    raw=path.read_bytes()
    ext=name.lower().rsplit('.',1)[-1]
    if raw[:4]==b'glTF':ext='glb'
    vertices,triangles,notes=[],[],[]
    def vertex(v):
        if len(vertices)>=MESH_LIMIT*3:
            raise ValueError('Mesh exceeds preview vertex limit')
        v=[float(x) for x in v[:3]]
        if len(v)!=3 or not all(math.isfinite(x) for x in v):
            raise ValueError('Invalid vertex coordinates')
        vertices.append(v)
    def face(ids):
        if len(ids)>1024:
            raise ValueError('Face has too many vertices')
        for i in range(1,len(ids)-1):
            if len(triangles)>=MESH_LIMIT:
                raise ValueError('Mesh exceeds 150,000 triangle preview limit')
            tri=[ids[0],ids[i],ids[i+1]]
            if min(tri)<0 or max(tri)>=len(vertices):
                raise ValueError('Face index outside vertex array')
            triangles.append(tri)
    if ext=='obj':
        for line in raw.decode('utf-8','replace').splitlines():
            words=line.split('#',1)[0].split()
            if not words:
                continue
            if words[0]=='v':
                vertex(words[1:4])
            elif words[0]=='f':
                ids=[int(x.split('/')[0]) for x in words[1:]]
                face([x-1 if x>0 else len(vertices)+x for x in ids])
        notes.append('Geometry only; materials and textures are not loaded. Polygon faces use fan triangulation.')
    elif ext=='stl':
        count=struct.unpack_from('<I',raw,80)[0] if len(raw)>=84 else -1
        if count>=0 and 84+count*50==len(raw):
            if count>MESH_LIMIT:
                raise ValueError('STL exceeds triangle preview limit')
            for i in range(count):
                values=struct.unpack_from('<12f',raw,84+i*50)
                base=len(vertices)
                for j in (3,6,9):
                    vertex(values[j:j+3])
                face([base,base+1,base+2])
        else:
            for match in re.finditer(r'\bvertex\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)',raw.decode('ascii','replace'),re.I):
                vertex(match.groups())
                if len(vertices)%3==0:
                    face([len(vertices)-3,len(vertices)-2,len(vertices)-1])
    elif ext=='ply':
        lines=raw.decode('ascii','strict').splitlines()
        if not any(line.startswith('format ascii ') for line in lines[:20]):
            raise ValueError('Only ASCII PLY is supported by the built-in renderer')
        end=lines.index('end_header');nv=nf=0;props=[];element=None
        for line in lines[:end]:
            w=line.split()
            if w[:2]==['element','vertex']:
                nv=int(w[2]);element='vertex'
            elif w[:2]==['element','face']:
                nf=int(w[2]);element='face'
            elif w and w[0]=='element':
                element='other'
            elif w and w[0]=='property' and element=='vertex':
                if w[1]=='list':
                    raise ValueError('PLY vertex list properties not supported')
                props.append(w[-1])
        if nv>MESH_LIMIT*3 or nf>MESH_LIMIT:
            raise ValueError('PLY exceeds preview limit')
        indices=[props.index(c) for c in ('x','y','z')]
        for line in lines[end+1:end+1+nv]:
            w=line.split();vertex([w[i] for i in indices])
        for line in lines[end+1+nv:end+1+nv+nf]:
            w=line.split();count=int(w[0]);face([int(x) for x in w[1:1+count]])
        notes.append('ASCII PLY positions and faces; colors are not rendered.')
    elif ext in ('glb','gltf'):
        buffers=[]
        if ext=='glb':
            magic,version,total=struct.unpack_from('<4sII',raw,0)
            if magic!=b'glTF' or version!=2 or total!=len(raw):
                raise ValueError('Invalid GLB 2 header')
            off=12;doc=None
            while off+8<=len(raw):
                size,kind=struct.unpack_from('<II',raw,off);off+=8
                if off+size>len(raw):
                    raise ValueError('Truncated GLB chunk')
                if kind==0x4e4f534a:
                    doc=json.loads(raw[off:off+size])
                elif kind==0x004e4942:
                    buffers.append(raw[off:off+size])
                off+=size
            if doc is None:
                raise ValueError('Missing GLB JSON chunk')
        else:
            doc=json.loads(raw)
            for buf in doc.get('buffers',[]):
                uri=buf.get('uri','')
                if not uri.startswith('data:') or ';base64,' not in uri:
                    raise ValueError('glTF preview requires embedded data buffers; use GLB for external-buffer models')
                buffers.append(base64.b64decode(uri.split(',',1)[1],validate=True))
        def accessor(index):
            a=doc['accessors'][index]
            if 'sparse' in a or 'bufferView' not in a:
                raise ValueError('Sparse glTF accessors are not supported')
            v=doc['bufferViews'][a['bufferView']]
            buf=buffers[v['buffer']]
            fmts={5120:'b',5121:'B',5122:'h',5123:'H',5125:'I',5126:'f'}
            components={'SCALAR':1,'VEC2':2,'VEC3':3,'VEC4':4}
            fmt='<'+fmts[a['componentType']]*components[a['type']]
            width=struct.calcsize(fmt);stride=v.get('byteStride',width)
            if stride<width or a['count']>MESH_LIMIT*3:
                raise ValueError('glTF accessor exceeds preview limits')
            start=v.get('byteOffset',0)+a.get('byteOffset',0)
            end=v.get('byteOffset',0)+v['byteLength']
            values=[]
            for i in range(a['count']):
                p=start+i*stride
                if p+width>min(end,len(buf)):
                    raise ValueError('glTF accessor outside buffer view')
                values.append(struct.unpack_from(fmt,buf,p))
            return values
        for mesh in doc.get('meshes',[]):
            for primitive in mesh.get('primitives',[]):
                if primitive.get('mode',4)!=4:
                    notes.append('Skipped non-triangle primitive');continue
                if 'POSITION' not in primitive.get('attributes',{}):
                    notes.append('Skipped primitive with no POSITION accessor');continue
                positions=accessor(primitive['attributes']['POSITION']);base=len(vertices)
                for v in positions:
                    vertex(v)
                ids=[x[0] for x in accessor(primitive['indices'])] if 'indices' in primitive else list(range(len(positions)))
                for i in range(0,len(ids)-2,3):
                    face([base+int(x) for x in ids[i:i+3]])
        notes.append('Mesh-local geometry only: scene/node transforms, skinning, animation, materials and textures are not applied. Draco compression is not supported.')
    else:
        raise ValueError('No built-in mesh renderer for this format')
    if not vertices:
        raise ValueError('No readable geometry found')
    return dict(vertices=vertices,triangles=triangles,notes=notes,vertex_count=len(vertices),triangle_count=len(triangles))
