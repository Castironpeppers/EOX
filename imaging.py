"""Cancelable read-only imaging jobs and a constrained FlashGBX backup adapter."""
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time


def flash_command():
    found=shutil.which('flashgbx') or shutil.which('FlashGBX')
    if found:return [found]
    if importlib.util.find_spec('FlashGBX'):return [sys.executable,'-m','FlashGBX']
    return None


def providers():
    drives=[]
    if os.name=='nt':
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            if ctypes.windll.kernel32.GetDriveTypeW(letter+':\\')==5:
                drives.append(dict(path='\\\\.\\'+letter+':',label=letter+': optical drive'))
    else:
        for p in Path('/dev').glob('sr[0-9]*'):drives.append(dict(path=str(p),label=p.name+' optical drive'))
    ports=[]
    try:
        from serial.tools import list_ports
        ports=[dict(port=p.device,description=p.description) for p in list_ports.comports()]
    except ImportError:pass
    return dict(optical_drives=drives,flashgbx=bool(flash_command()),ports=ports,
        note='Optical jobs read logical data sectors only. Cartridge backup uses a compatible FlashGBX reader (GB/GBC/GBA), or a ROM file exposed by a mounted cartridge adapter. No cartridge flashing or disc burning is performed.')


def device_length(file):
    """Ask the OS for logical block-device length, when the driver exposes it."""
    try:
        if os.name=='nt':
            import msvcrt
            value=ctypes.c_longlong();returned=ctypes.c_ulong()
            kernel=ctypes.windll.kernel32
            kernel.DeviceIoControl.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.POINTER(ctypes.c_ulong),ctypes.c_void_p]
            if kernel.DeviceIoControl(msvcrt.get_osfhandle(file.fileno()),0x7405c,None,0,ctypes.byref(value),8,ctypes.byref(returned),None):return value.value if value.value>0 else None
        elif sys.platform.startswith('linux'):
            import fcntl,struct
            raw=fcntl.ioctl(file.fileno(),0x80081272,bytes(8));length=struct.unpack('<Q',raw)[0]
            return length if length>0 else None
    except (OSError,ValueError):pass
    return None


class ImagingJobs:
    def __init__(self,folder,register):self.folder=Path(folder);self.register=register;self.jobs={};self.lock=threading.Lock()
    def start(self,settings):
        mode=settings.get('mode','file')
        if mode not in ('file','optical','cartridge'):raise ValueError('Choose file copy, optical dump or cartridge backup')
        with self.lock:
            if any(j['state']=='running' for j in self.jobs.values()):raise ValueError('An imaging job is running. Finish or cancel it first.')
            ident=secrets.token_urlsafe(18);output=self.folder/(ident+'.dump')
            job=dict(id=ident,state='running',mode=mode,bytes=0,total=None,error='',result=None,cancel=threading.Event(),process=None,
                started=time.time(),verified=False,output=output)
            if mode=='cartridge':
                platform=settings.get('platform','dmg')
                if platform not in ('dmg','agb'):raise ValueError('Choose GB/GBC or GBA cartridge mode')
                if not flash_command():raise ValueError('Install FlashGBX and connect a compatible cartridge reader, or use the mounted-ROM-file route')
                job['name']='cartridge.gba' if platform=='agb' else 'cartridge.gb'
            else:
                source=str(settings.get('source','')).strip().strip('"')
                if mode=='optical':
                    if source not in {d['path'] for d in providers()['optical_drives']}:raise ValueError('Select an enumerated optical drive')
                    job['name']='disc-dump.iso'
                else:
                    p=Path(source).expanduser().resolve(strict=True)
                    if not p.is_file():raise ValueError('File-copy source must be a regular file. Optical drives use the optical mode.')
                    source=str(p);job['total']=p.stat().st_size;display=Path(settings.get('display_name') or p.name);job['name']=display.stem+'-clone'+display.suffix
                    if job['total']>shutil.disk_usage(self.folder).free:raise ValueError('Not enough free space for this copy')
                job['source']=source
            self.jobs[ident]=job
            thread=threading.Thread(target=self._run,args=(job,settings),daemon=True);thread.start()
            return self.status(ident)
    def _run(self,job,settings):
        output=job['output']
        try:
            if job['mode']=='cartridge':
                command=flash_command();help_run=subprocess.run(command+['--help'],capture_output=True,timeout=15)
                help_text=(help_run.stdout+help_run.stderr).decode(errors='replace')
                if not all(flag in help_text for flag in ('--cli','--mode','--action')) or 'backup-rom' not in help_text:
                    raise ValueError('Installed FlashGBX CLI differs from this adapter. Use FlashGBX Backup ROM and import the result into EOX.')
                command+=['--cli','--mode',settings.get('platform','dmg'),'--action','backup-rom']
                port=str(settings.get('port','')).strip()
                if port:
                    if '--device-port' not in help_text:raise ValueError('This FlashGBX version cannot select a port through this adapter')
                    if port not in {p['port'] for p in providers()['ports']}:raise ValueError('Select an enumerated serial port')
                    command+=['--device-port',port]
                command+=[str(output)]
                log=self.folder/(job['id']+'.reader.log')
                with log.open('wb') as f:process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT)
                job['process']=process;deadline=time.monotonic()+1800
                while process.poll() is None:
                    if job['cancel'].wait(.2) or time.monotonic()>deadline:
                        process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait()
                        raise ValueError('Cartridge backup canceled or timed out')
                    if output.exists():job['bytes']=output.stat().st_size
                if process.returncode or not output.exists():raise ValueError('Cartridge reader: '+log.read_text(errors='replace')[-2000:])
                job['bytes']=output.stat().st_size;job['total']=job['bytes']
            else:
                digest=hashlib.sha256();expected_hash=None
                # Optical streams return logical sector data, not subchannel/audio sectors.
                with open(job['source'],'rb',buffering=0) as src,output.open('wb') as dst:
                    if job['mode']=='optical':job['total']=device_length(src)
                    if job['total'] and job['total']>shutil.disk_usage(self.folder).free:raise ValueError('Not enough free space for this image')
                    remaining=job['total']
                    while remaining is None or remaining>0:
                        if job['cancel'].is_set():raise ValueError('Imaging canceled')
                        block=src.read(min(1024*1024,remaining) if remaining is not None else 1024*1024)
                        if not block:
                            if remaining:raise ValueError('Source ended before its declared length')
                            break
                        dst.write(block);digest.update(block);job['bytes']+=len(block)
                        if remaining is not None:remaining-=len(block)
                if not job['bytes']:raise ValueError('Source returned no data. Check media and read permissions.')
                if settings.get('verify',True):
                    job['phase']='Verifying second read';check=hashlib.sha256()
                    with open(job['source'],'rb',buffering=0) as src:
                        remaining=job['bytes']
                        while remaining:
                            if job['cancel'].is_set():raise ValueError('Verification canceled')
                            block=src.read(min(1024*1024,remaining))
                            if not block:raise ValueError('Verification read ended early')
                            check.update(block);remaining-=len(block)
                        if job['mode']=='file' and src.read(1):raise ValueError('Source length changed during verification')
                    if check.digest()!=digest.digest():raise ValueError('Two source reads differ; the dump is not marked verified')
                    job['verified']=True
                expected_hash=digest.hexdigest()
            if job['cancel'].is_set():raise ValueError('Imaging canceled')
            job['phase']='Inspecting dump';result=self.register(output,job['name'])
            if job['mode']!='cartridge' and result['sha256']!=expected_hash:raise ValueError('Destination hash differs from copied source bytes')
            job['result']=result;job['state']='complete'
        except Exception as e:
            job['state']='canceled' if job['cancel'].is_set() else 'failed';job['error']=str(e);output.unlink(missing_ok=True)
        finally:job['process']=None
    def status(self,ident):
        if ident not in self.jobs:raise ValueError('Imaging job not found')
        j=self.jobs[ident];return {k:v for k,v in j.items() if k not in ('cancel','process','output','source')}
    def cancel(self,ident):
        if ident not in self.jobs:raise ValueError('Imaging job not found')
        self.jobs[ident]['cancel'].set();return self.status(ident)
    def close(self):
        for job in self.jobs.values():
            job['cancel'].set()
            process=job.get('process')
            if process and process.poll() is None:process.terminate()
