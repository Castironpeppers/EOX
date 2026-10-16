"""PCAP/PCAPNG parsing, readable protocol layers and opt-in dumpcap capture."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import threading
import time

PCAP_MAGIC={b'\xd4\xc3\xb2\xa1':('<',1e-6),b'\xa1\xb2\xc3\xd4':('>',1e-6),
            b'\x4d\x3c\xb2\xa1':('<',1e-9),b'\xa1\xb2\x3c\x4d':('>',1e-9)}
PACKET_LIMIT=20000
PACKET_BYTES_LIMIT=16*1024**2
STREAM_LIMIT=1024**2


def find_tool(name):
    found=shutil.which(name)
    if found:
        return found
    if os.name=='nt':
        for folder in (os.environ.get('ProgramFiles','C:\\Program Files'),os.environ.get('ProgramFiles(x86)','C:\\Program Files (x86)')):
            p=Path(folder)/'Wireshark'/(name+'.exe')
            if p.is_file():
                return str(p)
    return None


def local_addresses():
    addresses={'127.0.0.1','::1'}
    try:
        import psutil
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family in (socket.AF_INET,socket.AF_INET6):
                    addresses.add(entry.address.split('%')[0])
    except ImportError:
        try:
            for row in socket.getaddrinfo(socket.gethostname(),None):
                addresses.add(row[4][0].split('%')[0])
        except OSError:
            pass
        # Linux hostname resolution frequently omits the active adapter addresses.
        if os.name!='nt' and shutil.which('ip'):
            try:
                r=subprocess.run(['ip','-j','address'],capture_output=True,timeout=3)
                for adapter in json.loads(r.stdout):
                    for a in adapter.get('addr_info',[]):
                        addresses.add(a['local'])
            except (OSError,ValueError,subprocess.TimeoutExpired):
                pass
    return sorted(addresses)


def capture_records(path):
    """Yield bounded record descriptors. Partial tails are normal during live capture."""
    with Path(path).open('rb') as f:
        magic=f.read(4);f.seek(0)
        if magic in PCAP_MAGIC:
            header=f.read(24)
            if len(header)<24:
                raise ValueError('PCAP header is incomplete; bytes remain available')
            endian,res=PCAP_MAGIC[magic]
            _,major,minor,_,_,snap,link=struct.unpack(endian+'IHHIIII',header)
            if major!=2:
                raise ValueError('PCAP version requires deeper dissection; bytes remain available')
            link &= 0xffff
            for i in range(PACKET_LIMIT):
                h=f.read(16)
                if not h:
                    return
                if len(h)<16:
                    return
                sec,frac,cap,wire=struct.unpack(endian+'IIII',h)
                if cap>PACKET_BYTES_LIMIT:
                    raise ValueError('Packet record exceeds 16 MiB parse limit')
                offset=f.tell();raw=f.read(cap)
                if len(raw)!=cap:
                    return
                yield dict(number=i+1,offset=offset,captured=cap,length=wire,timestamp=sec+frac*res,
                           linktype=link,interface=0,raw=raw)
            return
        if magic!=b'\x0a\x0d\x0d\x0a':
            raise ValueError('Capture signature not recognized; raw bytes remain available')
        endian=None;interfaces=[];number=0
        while number<PACKET_LIMIT:
            start=f.tell();header=f.read(8)
            if len(header)<8:
                return
            if header[:4]==b'\x0a\x0d\x0d\x0a':
                bom=f.read(4)
                if bom==b'\x4d\x3c\x2b\x1a':
                    endian='<'
                elif bom==b'\x1a\x2b\x3c\x4d':
                    endian='>'
                else:
                    raise ValueError('Invalid PCAPNG byte-order mark')
                interfaces=[];f.seek(start+8)
            if endian is None:
                raise ValueError('PCAPNG section header missing')
            kind,length=struct.unpack(endian+'II',header)
            if length<12 or length%4 or length>PACKET_BYTES_LIMIT+4096:
                raise ValueError('Invalid or excessive PCAPNG block size')
            body=f.read(length-8)
            if len(body)!=length-8:
                return
            if struct.unpack_from(endian+'I',body,len(body)-4)[0]!=length:
                raise ValueError('PCAPNG block length mismatch')
            if kind==1 and length>=20:
                link,_,snap=struct.unpack_from(endian+'HHI',body,0)
                interface=dict(linktype=link,snap=snap,resolution=1e-6,time_offset=0)
                p=8
                while p+4<=len(body)-4:
                    code,n=struct.unpack_from(endian+'HH',body,p);p+=4
                    if code==0:
                        break
                    if p+n>len(body)-4:
                        raise ValueError('PCAPNG option outside block')
                    value=body[p:p+n];p+=(n+3)&~3
                    if code==9 and n==1:
                        interface['resolution']=(2 if value[0]&128 else 10)**(-(value[0]&127))
                    elif code==14 and n==8:
                        interface['time_offset']=struct.unpack(endian+'q',value)[0]
                    elif code==2:
                        interface['name']=value.decode('utf-8','replace')
                interfaces.append(interface)
            elif kind in (6,2) and length>=32:
                if kind==6:
                    ident,hi,lo,cap,wire=struct.unpack_from(endian+'IIIII',body,0)
                else:
                    ident,_,hi,lo,cap,wire=struct.unpack_from(endian+'HHIIII',body,0)
                if ident>=len(interfaces) or cap>len(body)-24:
                    raise ValueError('PCAPNG packet references missing interface or truncated data')
                interface=interfaces[ident];number+=1
                yield dict(number=number,offset=start+28,captured=cap,length=wire,
                    timestamp=((hi<<32)|lo)*interface['resolution']+interface['time_offset'],
                    linktype=interface['linktype'],interface=ident,raw=body[20:20+cap])
            elif kind==3 and length>=16 and interfaces:
                wire=struct.unpack_from(endian+'I',body,0)[0]
                snap=interfaces[0]['snap'] or wire;cap=min(wire,snap,len(body)-8);number+=1
                yield dict(number=number,offset=start+12,captured=cap,length=wire,timestamp=None,
                    linktype=interfaces[0]['linktype'],interface=0,raw=body[4:4+cap])


def dns_name(data,start):
    labels=[];p=start;end=None;visited=set()
    for _ in range(128):
        if p>=len(data) or p in visited:
            raise ValueError('Invalid DNS name')
        visited.add(p);n=data[p];p+=1
        if n & 0xc0==0xc0:
            if p>=len(data):
                raise ValueError('Truncated DNS pointer')
            target=((n&63)<<8)|data[p];p+=1
            end=end or p;p=target;continue
        if n==0:
            return '.'.join(labels),end or p
        if n>63 or p+n>len(data):
            raise ValueError('Truncated DNS label')
        labels.append(data[p:p+n].decode('ascii','replace'));p+=n
    raise ValueError('DNS name exceeds traversal limit')


def app_decode(payload,srcport,dstport):
    result={}
    if 53 in (srcport,dstport) and len(payload)>=12:
        try:
            ident,flags,qd,an,ns,ar=struct.unpack_from('!6H',payload)
            queries=[];answers=[];p=12
            for _ in range(min(qd,32)):
                name,p=dns_name(payload,p);qtype,qclass=struct.unpack_from('!HH',payload,p);p+=4
                queries.append(dict(name=name,type=qtype))
            for _ in range(min(an,32)):
                name,p=dns_name(payload,p);rtype,rclass,ttl,length=struct.unpack_from('!HHIH',payload,p);p+=10
                value=payload[p:p+length]
                if len(value)!=length:
                    raise ValueError('Truncated DNS answer')
                readable=socket.inet_ntop(socket.AF_INET,value) if rtype==1 and length==4 else socket.inet_ntop(socket.AF_INET6,value) if rtype==28 and length==16 else dns_name(payload,p)[0] if rtype in (2,5,12) else value.hex()
                answers.append(dict(name=name,type=rtype,value=readable,ttl=ttl));p+=length
            result=dict(application='DNS',dns=dict(id=ident,response=bool(flags&0x8000),queries=queries,answers=answers))
        except (ValueError,OSError,struct.error) as e:
            result=dict(application='DNS',decode_note=str(e))
    elif re.match(rb'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) |HTTP/\d',payload):
        header=payload.split(b'\r\n\r\n',1)[0][:16384].decode('iso-8859-1','replace')
        result=dict(application='HTTP',http_header=header)
    elif len(payload)>=5 and payload[0] in (20,21,22,23) and payload[1]==3:
        result=dict(application='TLS',tls=dict(record_type=payload[0],legacy_version=payload[1:3].hex(),
            record_length=int.from_bytes(payload[3:5],'big'),note='TLS record bytes are encrypted or handshake data; no decryption is attempted.'))
    return result


def decode_packet(raw,linktype,local_ips=()):
    d=dict(protocol='LINK',source='',destination='',source_port=None,destination_port=None,
           direction='Peer ↔ peer',layers=[],payload_offset=0,payload_size=len(raw),info='Raw link-layer data')
    pos=0;ether=None
    try:
        if linktype==1:
            if len(raw)<14:
                raise ValueError('Truncated Ethernet header')
            dest,src,ether=struct.unpack_from('!6s6sH',raw)
            d['layers'].append(dict(layer='Ethernet',source=src.hex(':'),destination=dest.hex(':'),type=hex(ether)))
            pos=14
            for _ in range(2):
                if ether not in (0x8100,0x88a8):break
                tag,ether=struct.unpack_from('!HH',raw,pos);pos+=4
                d['layers'].append(dict(layer='VLAN',id=tag&4095))
        elif linktype in (101,228,229):
            ether=0x86dd if raw and raw[0]>>4==6 else 0x800
        elif linktype in (0,108):
            family=struct.unpack_from('<I' if linktype==0 else '!I',raw)[0];pos=4
            ether=0x800 if family==2 else 0x86dd if family in (10,24,28,30) else None
        elif linktype==113:
            ether=struct.unpack_from('!H',raw,14)[0];pos=16
        elif linktype==276:
            ether=struct.unpack_from('!H',raw,0)[0];pos=20
        else:
            d['info']=f'Link type {linktype}; raw bytes available';return d
        if ether==0x806:
            hw,ptype,hlen,plen,op=struct.unpack_from('!HHBBH',raw,pos)
            if hlen==6 and plen==4 and len(raw)>=pos+28:
                src=socket.inet_ntoa(raw[pos+14:pos+18]);dst=socket.inet_ntoa(raw[pos+24:pos+28])
                d.update(protocol='ARP',source=src,destination=dst,info=f'ARP {"request" if op==1 else "reply" if op==2 else op}')
                d['layers'].append(dict(layer='ARP',operation=op,source_ip=src,target_ip=dst))
            d['payload_offset']=pos;d['payload_size']=len(raw)-pos
        elif ether in (0x800,0x86dd):
            fragmented=False
            if ether==0x800:
                if len(raw)<pos+20 or raw[pos]>>4!=4:
                    raise ValueError('Truncated or invalid IPv4 header')
                ihl=(raw[pos]&15)*4;total=struct.unpack_from('!H',raw,pos+2)[0]
                if ihl<20 or len(raw)<pos+ihl or total<ihl:
                    raise ValueError('Invalid IPv4 header size')
                end=min(len(raw),pos+total);proto=raw[pos+9]
                src=socket.inet_ntoa(raw[pos+12:pos+16]);dst=socket.inet_ntoa(raw[pos+16:pos+20])
                frag=struct.unpack_from('!H',raw,pos+6)[0];fragmented=bool(frag&0x3fff)
                d['layers'].append(dict(layer='IPv4',source=src,destination=dst,ttl=raw[pos+8],protocol=proto,
                                       fragment_offset=(frag&8191)*8,more_fragments=bool(frag&8192)))
                pos+=ihl
            else:
                if len(raw)<pos+40 or raw[pos]>>4!=6:
                    raise ValueError('Truncated or invalid IPv6 header')
                src=socket.inet_ntop(socket.AF_INET6,raw[pos+8:pos+24]);dst=socket.inet_ntop(socket.AF_INET6,raw[pos+24:pos+40])
                plen=struct.unpack_from('!H',raw,pos+4)[0];end=min(len(raw),pos+40+plen);proto=raw[pos+6]
                d['layers'].append(dict(layer='IPv6',source=src,destination=dst,hop_limit=raw[pos+7]))
                pos+=40
                for _ in range(8):
                    if proto not in (0,43,44,60,51):break
                    if pos+2>end:raise ValueError('Truncated IPv6 extension')
                    following=raw[pos];length=8 if proto==44 else (raw[pos+1]+2)*4 if proto==51 else (raw[pos+1]+1)*8
                    if proto==44:
                        fragmented=True
                    if pos+length>end:raise ValueError('IPv6 extension outside packet')
                    pos+=length;proto=following
            d.update(source=src,destination=dst,protocol={6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'}.get(proto,f'IP/{proto}'))
            if fragmented:
                d.update(info='IP fragment; packet bytes shown without transport reassembly',fragmented=True)
            elif proto==6:
                if pos+20>end:raise ValueError('Truncated TCP header')
                sport,dport,seq,ack,ctl,window,checksum,urgent=struct.unpack_from('!HHIIHHHH',raw,pos)
                length=((ctl>>12)&15)*4
                if length<20 or pos+length>end:raise ValueError('Invalid TCP data offset')
                flags=[name for bit,name in [(1,'FIN'),(2,'SYN'),(4,'RST'),(8,'PSH'),(16,'ACK'),(32,'URG'),(64,'ECE'),(128,'CWR')] if ctl&bit]
                d.update(source_port=sport,destination_port=dport,sequence=seq,acknowledgment=ack,
                         tcp_flags=flags,info=' '.join(flags),payload_sequence=(seq+(1 if ctl&2 else 0))&0xffffffff)
                d['layers'].append(dict(layer='TCP',source_port=sport,destination_port=dport,sequence=seq,
                    acknowledgment=ack,flags=flags,window=window,checksum=hex(checksum)))
                pos+=length
            elif proto==17:
                if pos+8>end:raise ValueError('Truncated UDP header')
                sport,dport,length,checksum=struct.unpack_from('!HHHH',raw,pos)
                if length<8:raise ValueError('Invalid UDP length')
                end=min(end,pos+length);pos+=8
                d.update(source_port=sport,destination_port=dport,info=f'UDP {sport} → {dport}')
                d['layers'].append(dict(layer='UDP',source_port=sport,destination_port=dport,length=length))
            elif proto in (1,58) and pos+4<=end:
                d['layers'].append(dict(layer=d['protocol'],type=raw[pos],code=raw[pos+1]));pos+=4
            d['payload_offset']=pos;d['payload_size']=max(0,end-pos)
            if not fragmented:
                payload=raw[pos:end]
                # DNS over TCP carries a two-byte message length prefix.
                appdata=payload[2:] if proto==6 and 53 in (d['source_port'],d['destination_port']) and len(payload)>=2 else payload
                d.update(app_decode(appdata,d['source_port'],d['destination_port']))
                if d.get('application')=='DNS':
                    names=[q['name'] for q in d.get('dns',{}).get('queries',[])]
                    d['info']='DNS '+('response ' if d.get('dns',{}).get('response') else 'query ')+', '.join(names)
                elif d.get('application')=='HTTP':d['info']=d['http_header'].splitlines()[0]
                elif d.get('application')=='TLS':d['info']='TLS record · encrypted / handshake'
        else:
            d['info']=f'EtherType {hex(ether or 0)}; raw bytes available'
        local=set(local_ips);source=d['source'] in local;dest=d['destination'] in local
        d['direction']='Local ↔ local' if source and dest else 'Send →' if source else '← Receive' if dest else 'Peer ↔ peer'
    except (ValueError,OSError,struct.error,IndexError) as e:
        d['decode_note']=str(e);d['info']='Partial decode · '+str(e)
        d['payload_offset']=min(pos,len(raw));d['payload_size']=len(raw)-d['payload_offset']
    return d


def analyze_capture(path,local_ips=()):
    packets=[];flows={};counts={};total=sent=received=0;warnings=[]
    try:
        for record in capture_records(path):
            raw=record.pop('raw');decoded=decode_packet(raw,record['linktype'],local_ips);p={**record,**decoded}
            protocol=p.get('application',p['protocol']);counts[protocol]=counts.get(protocol,0)+1
            total+=p['length'];sent+=p['length'] if p['direction']=='Send →' else 0
            received+=p['length'] if p['direction']=='← Receive' else 0
            a=(p['source'],p['source_port']);b=(p['destination'],p['destination_port'])
            # Canonical key uses JSON strings so absent ports never compare against ints.
            endpoints=sorted([a,b],key=lambda e:json.dumps(e));key=json.dumps([p['protocol'],endpoints,record['interface']])
            ident=hashlib.sha256(key.encode()).hexdigest()[:16];p['flow_id']=ident
            if ident not in flows:
                flows[ident]=dict(id=ident,protocol=p['protocol'],a=list(endpoints[0]),b=list(endpoints[1]),
                    packets=0,bytes=0,a_to_b=0,b_to_a=0,payload_bytes=0,applications=[])
            flow=flows[ident];flow['packets']+=1;flow['bytes']+=p['length'];flow['payload_bytes']+=p['payload_size']
            side='a_to_b' if list(a)==flow['a'] else 'b_to_a';flow[side]+=p['length'];p['flow_side']=side
            if p.get('application') and p['application'] not in flow['applications']:flow['applications'].append(p['application'])
            # Packet list stays compact; full layers are obtained on selection.
            p.pop('layers',None);p.pop('http_header',None);p.pop('dns',None);p.pop('tls',None)
            packets.append(p)
    except ValueError as e:
        warnings.append(str(e))
    return dict(packets=packets,flows=sorted(flows.values(),key=lambda f:-f['bytes']),protocols=counts,
        summary=dict(packets=len(packets),wire_bytes=total,send_bytes=sent,receive_bytes=received),
        local_ips=list(local_ips),warnings=warnings,limited=len(packets)>=PACKET_LIMIT,
        note='Direction uses the local IP addresses listed above. Imported captures may need their source machine addresses. Conversations aggregate endpoint tuples; reused TCP connections may share a row. No IP fragment reassembly or TLS decryption.')


def read_packet(path,descriptor):
    with Path(path).open('rb') as f:
        f.seek(descriptor['offset']);return f.read(descriptor['captured'])


def packet_detail(path,descriptor,local_ips):
    raw=read_packet(path,descriptor);d=decode_packet(raw,descriptor['linktype'],local_ips)
    payload=raw[d['payload_offset']:d['payload_offset']+d['payload_size']]
    return {**descriptor,**d,'raw_hex':raw.hex(),'payload_hex':payload.hex(),
        'payload_text':payload.decode('utf-8','replace'),
        'note':'Payload bytes are captured transport data. Encrypted/compressed data remains encoded; truncated snapshots may omit bytes.'}


def conversation_data(path,packets,flow_id):
    selected=[p for p in packets if p['flow_id']==flow_id]
    if not selected:raise ValueError('Conversation not found')
    result=dict(flow_id=flow_id,note='TCP segments are ordered by sequence, with retransmission overlap trimmed. Gaps remain separate segments. UDP datagrams stay separate. No decryption, decompression or full application-object reconstruction.',directions={})
    for side in ('a_to_b','b_to_a'):
        rows=[p for p in selected if p['flow_side']==side and p['payload_size'] and not p.get('fragmented')]
        parts=[];limited=False;overlap=0;total=0
        if selected[0]['protocol']=='TCP' and rows:
            anchor=rows[0].get('payload_sequence',0)
            rows.sort(key=lambda p:((p.get('payload_sequence',0)-anchor+2**31)%2**32)-2**31)
            for p in rows:
                seq=((p.get('payload_sequence',0)-anchor+2**31)%2**32)-2**31
                raw=read_packet(path,p);chunk=raw[p['payload_offset']:p['payload_offset']+p['payload_size']]
                if parts and seq<=parts[-1][0]+len(parts[-1][1]):
                    end=parts[-1][0]+len(parts[-1][1]);trim=min(len(chunk),max(0,end-seq));overlap+=trim;chunk=chunk[trim:]
                    if chunk:parts[-1][1].extend(chunk[:max(0,STREAM_LIMIT-total)])
                elif chunk:
                    parts.append([seq,bytearray(chunk[:max(0,STREAM_LIMIT-total)])])
                total+=len(chunk)
                if total>=STREAM_LIMIT:limited=True;break
        else:
            for p in rows:
                raw=read_packet(path,p);chunk=raw[p['payload_offset']:p['payload_offset']+p['payload_size']]
                parts.append([p['number'],bytearray(chunk[:max(0,STREAM_LIMIT-total)])]);total+=len(chunk)
                if total>=STREAM_LIMIT:limited=True;break
        result['directions'][side]=dict(overlap_bytes_trimmed=overlap,limited=limited,
            segments=[dict(index=i,position=pos,bytes=len(data),hex=data.hex(),text=bytes(data).decode('utf-8','replace')) for i,(pos,data) in enumerate(parts)])
    return result


class CaptureManager:
    def __init__(self,folder):
        self.folder=Path(folder);self.lock=threading.RLock();self.sessions={};self.current=None
    def interfaces(self):
        tool=find_tool('dumpcap');rows=[];note=''
        if tool:
            try:
                r=subprocess.run([tool,'-D'],capture_output=True,timeout=10)
                for line in r.stdout.decode('utf-8','replace').splitlines():
                    match=re.match(r'^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?',line)
                    if match:rows.append(dict(id=match[1],name=match[2],description=match[3] or match[2]))
                if r.returncode:note=r.stderr.decode('utf-8','replace')[-2000:]
            except (OSError,subprocess.TimeoutExpired) as e:note=str(e)
        else:
            note='Live packet capture needs Wireshark/dumpcap. On Windows install Wireshark with Npcap. PCAP/PCAPNG files can already be opened without it.'
        return dict(interfaces=rows,dumpcap=bool(tool),tshark=bool(find_tool('tshark')),note=note,local_ips=local_addresses())
    def start(self,interface,duration=120,capture_filter=''):
        with self.lock:
            if self.current and self.sessions[self.current]['process'].poll() is None:
                raise ValueError('A capture is already running; stop it before starting another')
            available=self.interfaces();allowed={r['id'] for r in available['interfaces']}
            if str(interface) not in allowed:raise ValueError(available['note'] or 'Select an available capture interface')
            duration=max(1,min(600,int(duration)));capture_filter=str(capture_filter)[:512]
            ident=secrets.token_urlsafe(18);path=self.folder/(ident+'.pcapng');errorpath=self.folder/(ident+'.capture.log')
            cmd=[find_tool('dumpcap'),'-i',str(interface),'-p','-s','65535','-a',f'duration:{duration}',
                 '-a','filesize:131072','-c',str(PACKET_LIMIT),'-w',str(path)]
            if capture_filter:cmd+=['-f',capture_filter]
            with errorpath.open('wb') as log:
                process=subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=log)
            self.sessions[ident]=dict(process=process,path=path,errorpath=errorpath,started=time.time(),duration=duration)
            self.current=ident
            return self.status(ident)
    def status(self,ident=None):
        with self.lock:
            ident=ident or self.current
            if ident not in self.sessions:return dict(running=False,id=None)
            s=self.sessions[ident];code=s['process'].poll();error=''
            if code not in (None,0) and not s.get('stopped'):error=s['errorpath'].read_text(errors='replace')[-2000:]
            return dict(id=ident,running=code is None,exit_code=code,started=s['started'],duration=s['duration'],
                size=s['path'].stat().st_size if s['path'].exists() else 0,error=error)
    def path(self,ident):
        with self.lock:
            if ident not in self.sessions:raise ValueError('Capture session not found')
            return self.sessions[ident]['path']
    def stop(self,ident=None):
        with self.lock:
            ident=ident or self.current
            if ident in self.sessions:
                self.sessions[ident]['stopped']=True
                process=self.sessions[ident]['process']
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
            return self.status(ident)
    def close(self):
        for ident in list(self.sessions):self.stop(ident)


def deep_dissection(path,number):
    tool=find_tool('tshark')
    if not tool:
        return dict(note='Install Wireshark/TShark for its additional protocol dissectors. Native packet layers and payload bytes are already shown.')
    # No name resolution or external decryption keys are used.
    run=subprocess.run([tool,'-n','-r',str(path),'-Y',f'frame.number == {int(number)}',
                        '-T','json','-x'],capture_output=True,timeout=30)
    if run.returncode:raise ValueError(run.stderr.decode('utf-8','replace')[-2000:])
    if len(run.stdout)>8*1024**2:raise ValueError('Detailed dissection exceeds 8 MiB view limit')
    return dict(layers=json.loads(run.stdout))
