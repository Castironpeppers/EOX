"""Explicit HTTP(S) URL playback. No browser session/cookies or ad webpage player."""
import importlib.util
import json
import re
import secrets
import shutil
import subprocess
import sys
import threading
from urllib.parse import urlparse
from urllib.request import Request,urlopen,build_opener,HTTPRedirectHandler


def validate_url(value):
    value=str(value).strip();p=urlparse(value)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or any(c in value for c in '\r\n'):
        raise ValueError('Enter an HTTP(S) media URL without embedded credentials')
    return value


class Redirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        validate_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def request_url(url,headers=None,method=None):
    return build_opener(Redirect()).open(Request(validate_url(url),headers=headers or {},method=method),timeout=20)


def extractor_command():
    found=shutil.which('yt-dlp')
    if found:return [found]
    if importlib.util.find_spec('yt_dlp'):return [sys.executable,'-m','yt_dlp']
    return None


class URLStreams:
    def __init__(self):self.items={};self.processes=set();self.owners={};self.lock=threading.Lock()
    def resolve(self,value,mode='auto'):
        if mode not in ('auto','direct','page'):raise ValueError('Choose auto, direct or website-page resolution')
        url=validate_url(value);path=urlparse(url).path.lower();direct=bool(re.search(r'\.(mp4|webm|mp3|m4a|aac|ogg|oga|opus|wav|flac|m3u8|mpd|ts)$',path))
        headers={'User-Agent':'EOX/0.5'};title=path.rsplit('/',1)[-1] or 'URL media';protocol='direct';note=''
        if mode=='page' or (mode=='auto' and not direct and extractor_command()):
            command=extractor_command()
            if not command:raise ValueError('Install optional yt-dlp to resolve website pages. Direct media URLs already work.')
            # Ignoring config avoids loading cookies, browser sessions or user-supplied downloader hooks.
            run=subprocess.run(command+['--ignore-config','--no-playlist','--skip-download','--no-warnings',
                '--dump-single-json','-f','best[vcodec!=none][acodec!=none]/bestaudio/best','--',url],
                capture_output=True,timeout=50)
            if run.returncode:raise ValueError('Media URL extraction: '+run.stderr.decode(errors='replace')[-2000:])
            if len(run.stdout)>16*1024**2:raise ValueError('URL metadata exceeds the basic player limit')
            info=json.loads(run.stdout);url=validate_url(info.get('url',''));title=info.get('title',title);protocol=info.get('protocol','direct')
            for key,val in info.get('http_headers',{}).items():
                if key.lower() in ('user-agent','referer','origin') and not any(c in str(val) for c in '\r\n'):headers[key]=str(val)
            note='Site media extracted without loading its webpage player. Combined video/audio is preferred; some sites only expose audio or formats that need transcoding.'
        mime='application/octet-stream'
        try:
            with request_url(url,headers,method='HEAD') as response:
                mime=response.headers.get('Content-Type',mime).split(';')[0];url=validate_url(response.url)
        except Exception:
            pass
        manifest='m3u8' in protocol or 'dash' in protocol or urlparse(url).path.lower().endswith(('.m3u8','.mpd')) or mime in ('application/vnd.apple.mpegurl','application/x-mpegURL','application/dash+xml')
        ident=secrets.token_urlsafe(24)
        self.items[ident]=dict(url=url,headers=headers,title=title,mime=mime,manifest=manifest)
        return dict(id=ident,title=title,mime=mime,manifest=manifest,ffmpeg=bool(shutil.which('ffmpeg')),
            note=note+' EOX plays media, not page ads. Ads already stitched into the stream remain; DRM/license-protected playback is not implemented.',
            playback='/api/url/play?stream='+ident,transcoded='/api/url/transcode?stream='+ident)
    def get(self,ident):
        if ident not in self.items:raise ValueError('URL stream session not found')
        return self.items[ident]
    def proxy(self,handler,ident):
        item=self.get(ident);headers=dict(item['headers'])
        if handler.headers.get('Range'):headers['Range']=handler.headers['Range']
        with request_url(item['url'],headers) as response:
            if 'text/html' in response.headers.get('Content-Type',''):raise ValueError('This URL returns a webpage. Choose Resolve website page or provide a direct media URL.')
            handler.send_response(response.status)
            for key in ('Content-Type','Content-Length','Content-Range','Accept-Ranges'):
                if response.headers.get(key):handler.send_header(key,response.headers[key])
            handler.send_header('X-Content-Type-Options','nosniff');handler.send_header('Cache-Control','no-store');handler.end_headers()
            try:
                while block:=response.read(65536):handler.wfile.write(block)
            except (BrokenPipeError,ConnectionResetError):pass
    def transcode(self,handler,ident):
        item=self.get(ident);tool=shutil.which('ffmpeg')
        if not tool:raise ValueError('Install FFmpeg for HLS/DASH or browser-compatible URL transcoding')
        with self.lock:
            if len(self.processes)>=2:raise ValueError('Two URL transcoders are already active. Stop a player first.')
            headers=''.join(f'{k}: {v}\r\n' for k,v in item['headers'].items())
            cmd=[tool,'-v','error','-nostdin','-protocol_whitelist','http,https,tcp,tls,crypto','-headers',headers,
                '-rw_timeout','15000000','-i',item['url'],'-map','0:v:0?','-map','0:a:0?','-c:v','libx264','-preset','veryfast','-pix_fmt','yuv420p',
                '-c:a','aac','-f','mp4','-movflags','frag_keyframe+empty_moov+default_base_moof','pipe:1']
            process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);self.processes.add(process);self.owners[process]=ident
        try:
            first=process.stdout.read(4096)
            if not first:raise ValueError('FFmpeg could not open/decode this URL. Check whether the stream needs authentication, a license, or a refreshed URL.')
            handler.send_response(200);handler.send_header('Content-Type','video/mp4');handler.send_header('Cache-Control','no-store');handler.end_headers();handler.wfile.write(first)
            try:
                while block:=process.stdout.read(65536):handler.wfile.write(block)
            except (BrokenPipeError,ConnectionResetError):pass
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            process.stdout.close()
            with self.lock:self.processes.discard(process);self.owners.pop(process,None)
    def stop(self,ident):
        self.get(ident)
        with self.lock:
            for process in list(self.processes):
                if self.owners.get(process)==ident and process.poll() is None:process.terminate()
        return dict(stopped=True)
    def close(self):
        with self.lock:
            for process in list(self.processes):
                if process.poll() is None:process.terminate()
