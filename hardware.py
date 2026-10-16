"""Read-only host metrics and inventory. Optional psutil enriches the views."""
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import threading
import time

try:
    import psutil
except ImportError:
    psutil=None

LOCK=threading.Lock()
PREVIOUS={}
CACHE={}


def powershell(mode):
    if mode not in ('hardware','drivers','processes','connections','sensors'):
        raise ValueError('Unknown Windows inventory query')
    executable=shutil.which('powershell') or shutil.which('pwsh')
    if not executable:
        return dict(note='PowerShell is needed to query Windows CIM inventory.')
    script=Path(__file__).with_name('hardware.ps1').read_text(encoding='utf-8')
    # Fixed, bundled query via -Command works with Windows' default script-file policy.
    r=subprocess.run([executable,'-NoLogo','-NoProfile','-NonInteractive','-Command',
        '& { '+script+' } -Mode '+mode],capture_output=True,timeout=35)
    if r.returncode:
        return dict(note=r.stderr.decode('utf-8','replace')[-2000:])
    try:return json.loads(r.stdout.decode('utf-8-sig'))
    except ValueError:return dict(note='Windows inventory returned no readable JSON.')


def text(path,default=''):
    try:return Path(path).read_text(errors='replace').strip()
    except OSError:return default


def cpu_ticks():
    if os.name=='nt':
        idle=ctypes.c_ulonglong();kernel=ctypes.c_ulonglong();user=ctypes.c_ulonglong()
        if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle),ctypes.byref(kernel),ctypes.byref(user)):
            return None
        return kernel.value+user.value,idle.value
    line=text('/proc/stat').splitlines()
    if line and line[0].startswith('cpu '):
        values=[int(x) for x in line[0].split()[1:9]]
        return sum(values),values[3]+values[4]
    return None


def memory():
    if psutil:
        m=psutil.virtual_memory();return dict(total=m.total,available=m.available,used=m.total-m.available,percent=m.percent)
    if os.name=='nt':
        class MemoryStatus(ctypes.Structure):
            _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong),('total',ctypes.c_ulonglong),
                ('available',ctypes.c_ulonglong),('page_total',ctypes.c_ulonglong),('page_available',ctypes.c_ulonglong),
                ('virtual_total',ctypes.c_ulonglong),('virtual_available',ctypes.c_ulonglong),('extended',ctypes.c_ulonglong)]
        m=MemoryStatus();m.length=ctypes.sizeof(m)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            return dict(total=m.total,available=m.available,used=m.total-m.available,percent=m.load)
    values={}
    for line in text('/proc/meminfo').splitlines():
        key,_,value=line.partition(':')
        try:values[key]=int(value.split()[0])*1024
        except (ValueError,IndexError):pass
    total=values.get('MemTotal');available=values.get('MemAvailable')
    if total and available is not None:return dict(total=total,available=available,used=total-available,percent=round(100*(total-available)/total,1))
    return dict(note='Memory counters are not exposed by this OS without psutil.')


def network_counters():
    if psutil:
        return {k:dict(sent=v.bytes_sent,received=v.bytes_recv,packets_sent=v.packets_sent,packets_received=v.packets_recv)
                for k,v in psutil.net_io_counters(pernic=True).items()}
    result={}
    for line in text('/proc/net/dev').splitlines()[2:]:
        name,_,rest=line.partition(':');v=rest.split()
        if len(v)>=10:result[name.strip()]=dict(received=int(v[0]),packets_received=int(v[1]),sent=int(v[8]),packets_sent=int(v[9]))
    if not result and os.name=='nt':
        # Aggregate Windows counters; per-adapter detail is enriched by psutil.
        class MibIfRow(ctypes.Structure):
            _fields_=[('name',ctypes.c_wchar*256),('index',ctypes.c_ulong),('type',ctypes.c_ulong),
                ('mtu',ctypes.c_ulong),('speed',ctypes.c_ulong),('phys_length',ctypes.c_ulong),
                ('physical',ctypes.c_ubyte*8),('admin',ctypes.c_ulong),('oper',ctypes.c_ulong),
                ('last_change',ctypes.c_ulong),('in_octets',ctypes.c_ulong),('in_ucast',ctypes.c_ulong),
                ('in_nucast',ctypes.c_ulong),('in_discards',ctypes.c_ulong),('in_errors',ctypes.c_ulong),
                ('in_unknown',ctypes.c_ulong),('out_octets',ctypes.c_ulong),('out_ucast',ctypes.c_ulong),
                ('out_nucast',ctypes.c_ulong),('out_discards',ctypes.c_ulong),('out_errors',ctypes.c_ulong),
                ('out_queue',ctypes.c_ulong),('description_length',ctypes.c_ulong),('description',ctypes.c_ubyte*256)]
        length=ctypes.c_ulong(0);api=ctypes.windll.iphlpapi.GetIfTable
        api(None,ctypes.byref(length),False)
        if 4<=length.value<=1024**2:
            buf=ctypes.create_string_buffer(length.value)
            if api(buf,ctypes.byref(length),False)==0:
                count=ctypes.c_ulong.from_buffer(buf).value
                for i in range(min(count,1024)):
                    off=4+i*ctypes.sizeof(MibIfRow)
                    if off+ctypes.sizeof(MibIfRow)>length.value:break
                    row=MibIfRow.from_buffer(buf,off)
                    name=bytes(row.description[:min(row.description_length,256)]).decode(errors='replace') or str(row.index)
                    result[name]=dict(sent=row.out_octets,received=row.in_octets,
                        packets_sent=row.out_ucast+row.out_nucast,packets_received=row.in_ucast+row.in_nucast,
                        note='Windows 32-bit adapter counters; rates reset when counters wrap.')
    return result


def sensors():
    rows=[]
    if psutil and hasattr(psutil,'sensors_temperatures'):
        try:
            for name,entries in psutil.sensors_temperatures().items():
                for e in entries:rows.append(dict(name=name+' / '+(e.label or 'temperature'),type='Temperature',value=e.current,unit='°C'))
        except (OSError,RuntimeError):pass
    if not rows and os.name!='nt':
        for hw in Path('/sys/class/hwmon').glob('hwmon*'):
            name=text(hw/'name',hw.name)
            for p in hw.glob('temp*_input'):
                try:rows.append(dict(name=name+' / '+text(p.with_name(p.name.replace('_input','_label')),p.stem),type='Temperature',value=float(text(p))/1000,unit='°C'))
                except ValueError:pass
            for p in hw.glob('fan*_input'):
                try:rows.append(dict(name=name+' / '+p.stem,type='Fan',value=float(text(p)),unit='RPM'))
                except ValueError:pass
    if os.name=='nt':
        cached=CACHE.get('sensors')
        if not cached or time.monotonic()-cached[0]>15:
            found=powershell('sensors');CACHE['sensors']=(time.monotonic(),found)
        found=CACHE['sensors'][1]
        rows.extend(found.get('sensors',[]))
    return rows


def gpu_metrics():
    tool=shutil.which('nvidia-smi')
    if not tool and os.name=='nt':
        p=Path(os.environ.get('SystemRoot','C:\\Windows'))/'System32'/'nvidia-smi.exe'
        if p.is_file():tool=str(p)
    if not tool:return []
    try:
        r=subprocess.run([tool,'--query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total,power.draw',
            '--format=csv,noheader,nounits'],capture_output=True,timeout=4)
        import csv
        rows=[]
        for row in csv.reader(r.stdout.decode('utf-8','replace').splitlines()):
            if len(row)==6:rows.append(dict(zip(('name','load_percent','temperature_c','memory_used_mib','memory_total_mib','power_w'),[v.strip() for v in row])))
        return rows
    except (OSError,subprocess.TimeoutExpired):return []


def monitor():
    with LOCK:
        now=time.monotonic();ticks=cpu_ticks();usage=None
        if psutil:usage=psutil.cpu_percent(interval=None)
        elif ticks and 'cpu' in PREVIOUS:
            total=ticks[0]-PREVIOUS['cpu'][0];idle=ticks[1]-PREVIOUS['cpu'][1]
            if total>0:usage=round(max(0,min(100,100*(total-idle)/total)),1)
        if ticks:PREVIOUS['cpu']=ticks
        net=network_counters();previous=PREVIOUS.get('network',{});elapsed=now-PREVIOUS.get('time',now)
        for name,row in net.items():
            old=previous.get(name)
            row['send_per_second']=max(0,row['sent']-old['sent'])/elapsed if old and elapsed>0 else None
            row['receive_per_second']=max(0,row['received']-old['received'])/elapsed if old and elapsed>0 else None
        PREVIOUS['network']={k:dict(v) for k,v in net.items()};PREVIOUS['time']=now
        disks=[]
        roots=[str(Path.home().anchor)]
        if psutil:
            try:roots=sorted({p.mountpoint for p in psutil.disk_partitions()})
            except OSError:pass
        for root in roots:
            try:
                d=shutil.disk_usage(root);disks.append(dict(path=root,total=d.total,used=d.used,free=d.free,percent=round(d.used/d.total*100,1)))
            except OSError:pass
        return dict(timestamp=time.time(),cpu_percent=usage,logical_cpus=os.cpu_count(),memory=memory(),network=net,
            disks=disks,sensors=sensors(),gpus=gpu_metrics(),psutil=bool(psutil),
            note='Counters describe this machine, not packet payloads. Temperatures/fans require exposed sensors. On Windows run LibreHardwareMonitor with its WMI provider for CPU/board sensors. NVIDIA metrics use nvidia-smi. No sensor reading is invented.')


def normalize_driver_path(raw):
    value=str(raw or '').strip()
    if value.startswith('"'):
        value=value.split('"',2)[1]
    elif re.search(r'\.(sys|exe|dll)(?:\s|$)',value,re.I):
        value=re.split(r'(?<=\.sys)\s|(?<=\.exe)\s|(?<=\.dll)\s',value,1,flags=re.I)[0]
    if value.startswith('\\??\\'):value=value[4:]
    systemroot=os.environ.get('SystemRoot','C:\\Windows')
    if value.lower().startswith('\\systemroot\\'):value=systemroot+value[len('\\SystemRoot'):]
    value=os.path.expandvars(value)
    if value.lower().startswith('system32\\'):value=systemroot+'\\'+value
    return value


def inventory(section='hardware'):
    if section not in ('hardware','drivers','processes','connections'):raise ValueError('Unknown inventory section')
    ttl=3 if section in ('processes','connections') else 60
    cached=CACHE.get(section)
    if cached and time.monotonic()-cached[0]<ttl:return cached[1]
    result=dict(section=section,os=platform.platform(),hostname=socket.gethostname(),rows=[],note='')
    if section=='processes' and psutil:
        for p in psutil.process_iter(['pid','name','exe','memory_info','status']):
            try:
                i=p.info;m=i.pop('memory_info',None);i['memory_bytes']=m.rss if m else None;i['path']=i.pop('exe',None);result['rows'].append(i)
            except (psutil.AccessDenied,psutil.NoSuchProcess):pass
    elif section=='connections' and psutil:
        try:
            for c in psutil.net_connections(kind='inet'):
                result['rows'].append(dict(local=list(c.laddr),remote=list(c.raddr),state=c.status,pid=c.pid,
                                           protocol='TCP' if c.type==socket.SOCK_STREAM else 'UDP'))
        except (psutil.AccessDenied,OSError):result['note']='Connection owners require additional OS privileges on this machine.'
    elif os.name=='nt':
        result.update(powershell(section))
        if section=='drivers':
            for row in result.get('rows',[]):row['path']=normalize_driver_path(row.get('PathName'))
    elif section=='hardware':
        cpu=text('/proc/cpuinfo');model=next((line.split(':',1)[1].strip() for line in cpu.splitlines() if line.startswith('model name')),platform.processor())
        result.update(cpu=model,logical_cpus=os.cpu_count(),memory=memory(),board={k:text('/sys/class/dmi/id/'+v) for k,v in {'vendor':'board_vendor','name':'board_name','bios':'bios_version'}.items()},
            pci=[dict(address=p.name,vendor=text(p/'vendor'),device=text(p/'device'),class_code=text(p/'class'),driver=(p/'driver').resolve().name if (p/'driver').exists() else '') for p in Path('/sys/bus/pci/devices').glob('*')])
    elif section=='drivers':
        for line in text('/proc/modules').splitlines():
            w=line.split()
            if len(w)>=6:result['rows'].append(dict(name=w[0],size=int(w[1]),references=int(w[2]),state=w[4],address=w[5],path=''))
        result['note']='Loaded Linux modules. Windows hosts expose .sys paths through CIM.'
    elif section=='processes':
        for p in list(Path('/proc').glob('[0-9]*'))[:4096]:
            try:
                status=text(p/'status');rss=re.search(r'^VmRSS:\s+(\d+)',status,re.M)
                result['rows'].append(dict(pid=int(p.name),name=text(p/'comm'),path=os.readlink(p/'exe'),memory_bytes=int(rss[1])*1024 if rss else None))
            except OSError:pass
    elif section=='connections':
        tool=shutil.which('ss') or shutil.which('netstat')
        if tool:
            r=subprocess.run([tool,'-tunap'] if Path(tool).name=='ss' else [tool,'-ano'],capture_output=True,timeout=5)
            result['text']=r.stdout.decode('utf-8','replace')[:1024**2]
        else:result['note']='Install psutil to expose the local connection table and process owners.'
    result['rows']=result.get('rows',[])[:4096]
    CACHE[section]=(time.monotonic(),result)
    return result
