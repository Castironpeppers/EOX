"""Range/content ancestry guards and cumulative navigation resource reservations."""
from contextlib import contextmanager
import hashlib
import threading


class CycleError(ValueError):pass


def ancestors(files,parent_id):
    seen=set();node=parent_id
    while node:
        if node in seen:raise CycleError('Cycle in navigation metadata; reopen the source as a new root.')
        seen.add(node);item=files.get(node)
        if item is None:raise CycleError('Navigation ancestor is missing; reopen the source.')
        yield node,item
        node=item['data'].get('provenance',{}).get('parent_id')


def byte_range(source_id,start,length):
    return dict(source_object_id=source_id,start=start,end=start+length,length=length)


def root_provenance(ident,size):
    return dict(relation='root',parent_id=None,byte_range=byte_range(ident,0,size),storage_range=None)


def slice_range(parent_id,parent,offset,length):
    if offset<0 or length<0 or offset+length>parent['data']['size']:raise ValueError('Child byte range exceeds its parent')
    base=parent['data']['provenance']['byte_range']
    return byte_range(base['source_object_id'],base['start']+offset,length)


def check_child(files,parent_id,size,digest,source_range=None):
    for ident,item in ancestors(files,parent_id):
        data=item['data'];previous=data.get('provenance',{}).get('byte_range')
        if source_range is not None and source_range==previous:
            raise CycleError('Recursion blocked: this child is the same byte range as '+data['name']+'. Inspect the current object or open its container members.')
        if size==data['size'] and digest==data['sha256']:
            raise CycleError('Recursion blocked: this child has identical content to ancestor '+data['name']+' (SHA-256 '+digest+').')


def child_provenance(files,ident,parent_id,size,digest,origin):
    parent=files[parent_id];relation=origin['relation']
    if relation=='embedded':
        coordinate=slice_range(parent_id,parent,origin['offset'],size);storage=coordinate
    elif relation=='member':
        # Decoded member bytes get their own coordinate system. Physical storage
        # has a separate range; compressed offsets are never labeled as decoded.
        coordinate=byte_range(ident,0,size);storage=origin.get('storage_range')
    else:raise ValueError('Invalid navigation relation')
    check_child(files,parent_id,size,digest,coordinate)
    return dict(relation=relation,parent_id=parent_id,parent_name=parent['data']['name'],
        byte_range=coordinate,storage_range=storage,member=origin.get('member'),
        member_index=origin.get('member_index'),encoding=origin.get('encoding','identity'),decoded_stream_offset=origin.get('decoded_stream_offset'))


def filter_scan(path,scan,files,parent_id):
    """Hide self/ancestor candidates, leaving explanatory non-clickable records.

    Hash work is bounded. Every actual open repeats an unconditional ancestry
    check, including candidates whose scan-time hash check hit the work budget.
    """
    item=files[parent_id];chain=list(ancestors(files,parent_id));remaining=128*1024**2
    out=[];blocked=[dict(c,sha256=item['data']['sha256'],source_range=item['data']['provenance']['byte_range']) for c in scan.get('current_object',[])]
    with path.open('rb') as source:
        for original in scan['candidates']:
            c=dict(original);length=c.get('size');reason=None
            if c.get('complete') is False:reason='Truncated object; declared range exceeds the parent file'
            if c['offset']==0 and length is None:reason='Top-level signature of the current object; no distinct boundary established'
            if length is not None and c.get('complete',False) and c['offset']+length<=item['data']['size']:
                coordinate=slice_range(parent_id,item,c['offset'],length);c['source_range']=coordinate
                if any(coordinate==ancestor['data'].get('provenance',{}).get('byte_range') for _,ancestor in chain):reason='Current/ancestor byte range; not an embedded child'
                if not reason and length<=remaining:
                    remaining-=length;source.seek(c['offset']);digest=hashlib.sha256();left=length
                    while left:
                        raw=source.read(min(left,1024**2))
                        if not raw:raise ValueError('Source changed during embedded scan; reopen it')
                        digest.update(raw);left-=len(raw)
                    c['sha256']=digest.hexdigest()
                    try:check_child(files,parent_id,length,c['sha256'],coordinate)
                    except CycleError as exc:reason=str(exc)
                elif not reason:c['cycle_check']='Checked when opened (scan hash budget reached)'
            if reason:c['reason']=reason;blocked.append(c)
            else:out.append(c)
    return dict(scan,candidates=out,blocked=blocked)


class NavigationBudget:
    """Reserve disk work before decoding; no fixed nesting-depth limit."""
    def __init__(self,max_bytes=512*1024**2,max_objects=10000):
        self.max_bytes=max_bytes;self.max_objects=max_objects;self.bytes=0;self.objects=0;self.lock=threading.Lock()
    @contextmanager
    def reserve(self,length):
        if length<0:raise ValueError('Invalid navigation size')
        with self.lock:
            if self.bytes+length>self.max_bytes:raise ValueError(f'Navigation byte budget reached ({self.max_bytes:,} bytes per session). Existing objects remain inspectable; restart EOX or raise --navigation-budget-mib.')
            if self.objects+1>self.max_objects:raise ValueError(f'Navigation object budget reached ({self.max_objects:,} children per session). Existing objects remain inspectable; raise --navigation-max-objects for a larger session.')
            self.bytes+=length;self.objects+=1
        lease={'committed':False,'bytes':length}
        try:yield lease
        finally:
            if not lease['committed']:
                with self.lock:self.bytes-=length;self.objects-=1
    def usage(self):
        with self.lock:return dict(bytes=self.bytes,objects=self.objects,max_bytes=self.max_bytes,max_objects=self.max_objects)
