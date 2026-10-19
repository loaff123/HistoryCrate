"""Historical paths and inert metadata from verified owned object stores."""
from __future__ import annotations

import re
import time
import os
from .monitor import CopyMonitor
from .paths import open_directory
from .native import _path, refuse

_ATTRIBUTES=('filter','text','eol','ident','working-tree-encoding')
_UNSET={'unspecified','unset'}
_NAME=re.compile(r'[A-Za-z0-9._/-]{1,200}\Z')


def walk_tree(reader, commit, job):
    """Return all nondirectory paths after validating every historical entry."""
    record=reader.commit(commit);files={};pending=[('',record.tree)]
    while pending:
        prefix,oid=pending.pop()
        if time.monotonic()-job.native.started>job.limits.job_wall_seconds:refuse('BUDGET_EXCEEDED',5,resource='job_wall_seconds')
        siblings=set()
        for entry in reader.tree(oid):
            try:name=entry.name.decode('utf-8','strict')
            except UnicodeError:refuse('UNSAFE_PATH',3,commit=commit)
            # A tree entry is one component, never a preassembled path.
            if '/' in name:refuse('UNSAFE_PATH',3,commit=commit)
            path=prefix+name;_path(path,job.limits)
            folded=name.casefold()
            if folded in siblings:refuse('PATH_COLLISION',3,commit=commit,path=path)
            siblings.add(folded);job.budget.charge('commit_path_visits',1)
            if entry.mode not in (0o40000,0o100644,0o100755,0o160000):refuse('UNSUPPORTED_TREE_MODE',3,commit=commit,path=path,mode=entry.mode)
            if name=='.lfsconfig':refuse('HISTORICAL_LFSCONFIG',3,commit=commit,path=path)
            if name in ('.gitmodules','.gitattributes') and entry.mode not in (0o100644,0o100755):refuse('INVALID_METADATA_MODE',3,commit=commit,path=path)
            if entry.mode==0o40000:pending.append((path+'/',entry.oid))
            else:files[path]=entry
    return files


def read_gitmodules(reader, commit):
    """Decode historical root .gitmodules without activating any configuration."""
    entry=next((x for x in reader.tree(reader.commit(commit).tree) if x.name==b'.gitmodules'),None)
    if entry is None:return {}
    if entry.mode not in (0o100644,0o100755):refuse('INVALID_METADATA_MODE',3,commit=commit,path='.gitmodules')
    cached=reader._cached(entry.oid,'gitmodules')
    info=reader.info(entry.oid)
    if info.kind!='blob':refuse('INVALID_METADATA_OBJECT',4,commit=commit)
    if info.size>reader.job.limits.gitmodules_bytes:refuse('BUDGET_EXCEEDED',5,resource='gitmodules_bytes')
    if info.size>reader.job.limits.config_bytes:refuse('BUDGET_EXCEEDED',5,resource='config_bytes')
    if cached is not None:
        paths,checked_paths=cached
        for path in checked_paths:_path(path,reader.job.limits)
        return dict(paths)
    _,raw=reader.read(entry.oid)
    path=reader.job.root/'historical-gitmodules';created=False
    try:
        with path.open('xb') as out:
            created=True
            out.write(raw)
        path.chmod(0o600)
        result=reader.job.native.run('parse_config',{'name':path.name})
        if result.stderr:refuse('INVALID_GITMODULES',3,commit=commit)
    finally:
        if created and path.exists():path.unlink()
    groups={}
    for field in result.stdout.split(b'\0'):
        if not field:continue
        try:key,value=field.split(b'\n',1);key=key.decode('utf-8','strict');value=value.decode('utf-8','strict')
        except (ValueError,UnicodeError):refuse('INVALID_GITMODULES',3,commit=commit)
        match=re.fullmatch(r'submodule\.(.+)\.([^.]+)',key)
        if not match or not _NAME.fullmatch(match[1]):refuse('INVALID_GITMODULES',3,commit=commit)
        name,leaf=match.groups()
        if leaf not in {'path','url','branch','ignore','shallow','fetchrecursesubmodules','update'}:refuse('INVALID_GITMODULES',3,commit=commit)
        values=groups.setdefault(name,{})
        if leaf in values:refuse('DUPLICATE_GITMODULES_KEY',3,commit=commit)
        if leaf=='update' and value not in {'checkout','rebase','merge','none'}:refuse('UNSUPPORTED_SUBMODULE_UPDATE',3,commit=commit)
        if any(ord(c)<32 or ord(c)==127 for c in value):refuse('INVALID_GITMODULES',3,commit=commit)
        values[leaf]=value
    paths={};seen=set()
    for name,values in groups.items():
        path=values.get('path')
        if path is None:continue # An incomplete inactive declaration has no edge.
        _path(path,reader.job.limits)
        if path in seen:refuse('DUPLICATE_GITMODULES_PATH',3,commit=commit,path=path)
        seen.add(path)
        if values.get('url'):paths[path]=(name,values['url'])
    # Keep only immutable parsed data. Each caller owns its mutable result map.
    reader._cache(entry.oid,'gitmodules',(tuple(sorted(paths.items())),tuple(sorted(seen))))
    return paths


def attributes_at(reader, commit, paths):
    result={}
    for start in range(0,len(paths),1000):
        selected=paths[start:start+1000]
        response=reader.job.native.run('check_attr',{'repo':reader.acquired.id,'commit':commit,'paths':selected})
        if response.stderr:refuse('INVALID_ATTRIBUTES',3,commit=commit)
        fields=response.stdout.split(b'\0')
        if fields[-1:]!=[b''] or (len(fields)-1)%3:refuse('INVALID_ATTRIBUTE_FRAME',4)
        for i in range(0,len(fields)-1,3):
            try:path,key,value=(x.decode('utf-8','strict') for x in fields[i:i+3])
            except UnicodeError:refuse('INVALID_ATTRIBUTE_FRAME',4)
            if path not in selected or key not in _ATTRIBUTES or key in result.setdefault(path,{}):refuse('INVALID_ATTRIBUTE_FRAME',4)
            result[path][key]=value
        for path in selected:
            values=result.get(path,{})
            if set(values)!=set(_ATTRIBUTES):refuse('INVALID_ATTRIBUTE_FRAME',4)
            if (values['filter'] not in _UNSET|{'lfs'} or values['ident'] not in _UNSET or values['working-tree-encoding'] not in _UNSET
                or values['text'] not in _UNSET|{'set','auto'} or values['eol'] not in _UNSET|{'lf','crlf'}):
                refuse('UNSUPPORTED_ATTRIBUTES',3,commit=commit,path=path)
            if values['filter']=='lfs' and (values['text']!='unset' or values['eol'] not in _UNSET):refuse('UNSUPPORTED_LFS_ATTRIBUTES',3,commit=commit,path=path)
    return result


def verify_conversion(reader, commit, path, blob_oid, attributes, job):
    """Native checkout conversion followed by native clean/hash, never status caches."""
    key=(reader.acquired.id,blob_oid,path,tuple(sorted(attributes.items())))
    cache=getattr(job,'_conversion_cache',None)
    if cache is None:cache=set();job._conversion_cache=cache
    if key in cache:return
    artifact=job.root/'artifacts'/'conversion-payload'
    size=reader.info(blob_oid).size
    may_expand=attributes.get('text') in ('set','auto') or (attributes.get('eol')=='crlf' and attributes.get('text')!='unset')
    monitor=CopyMonitor(job)
    parent_fd=open_directory(artifact.parent)
    try:monitor.allocation(parent_fd,size*(2 if may_expand else 1))
    finally:os.close(parent_fd)
    parameters={'repo':reader.acquired.id,'commit':commit,'path':path,'name':artifact.name};created=False
    try:
        job.native.run('conversion_checkout',{**parameters,'oid':blob_oid});created=True
        actual=job.native.run('conversion_hash',parameters).stdout
        if actual!=(blob_oid+'\n').encode():refuse('CLEAN_ROUNDTRIP_FAILED',4,repository=reader.acquired.id,commit=commit,path=path,blob_oid=blob_oid)
    finally:
        if created and artifact.exists():artifact.unlink()
    cache.add(key)
