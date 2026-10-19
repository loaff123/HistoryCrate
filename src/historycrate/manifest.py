"""Canonical semantic manifests. Native recomputation establishes truth separately."""
from dataclasses import asdict
import json
import re
from .errors import CrateError
from .limits import Limits
from .model import Closure,RootSpec,CommitRecord,ObjectRecord,GitlinkRecord,LfsOccurrence
from .schema import encode_canonical,_unique_object,_noninteger,_check_text_depth,_check_json_value,_object,_array,_id,_relative_path

OID=re.compile(r'[0-9a-f]{40}\Z');SHA=re.compile(r'[0-9a-f]{64}\Z')

def fail():raise CrateError('INVALID_MANIFEST',4)
def _oid(x):
    if not isinstance(x,str) or not OID.fullmatch(x):fail()
    return x
def _sha(x):
    if not isinstance(x,str) or not SHA.fullmatch(x):fail()
    return x
def _number(x,maximum):
    if type(x) is not int or not 0<=x<=maximum:fail()
    return x
def _unique(items,key=lambda x:x):
    if len({key(x) for x in items})!=len(items):fail()
    return items

def value(closure):
    payloads={}
    for item in closure.lfs:
        if payloads.setdefault(item.sha256,item.size)!=item.size:fail()
    return {'version':1,'profile':'trusted-local-v1',
        'repositories':[{'id':k,'seeds':sorted(v)} for k,v in sorted(closure.seeds.items())],
        'roots':[{'id':r.id,'repository':r.repository,'commits':sorted(r.commits),'ancestors':sorted(closure.root_ancestors[r.id])} for r in sorted(closure.roots,key=lambda x:x.id)],
        'commits':[asdict(x)|{'parents':list(x.parents)} for x in sorted(closure.commits,key=lambda x:(x.repository,x.oid))],
        'objects':[asdict(x) for x in sorted(closure.objects,key=lambda x:(x.repository,x.oid))],
        'gitlinks':[asdict(x) for x in sorted(closure.gitlinks,key=lambda x:(x.parent_repository,x.parent_commit,x.path))],
        'lfs':[asdict(x) for x in sorted(closure.lfs,key=lambda x:(x.repository,x.commit,x.path))],
        'payloads':[{'sha256':k,'size':v} for k,v in sorted(payloads.items())],
        'counts':{'repositories':len(closure.seeds),'roots':len(closure.roots),'commits':len(closure.commits),'objects':len(closure.objects),'gitlinks':len(closure.gitlinks),'lfs_occurrences':len(closure.lfs),'payloads':len(payloads),'payload_bytes':sum(payloads.values())}}

def encode_manifest(closure):return encode_canonical(value(closure))

def strict_json(data,limit):
    if type(data) is not bytes or len(data)>limit or data.startswith(b'\xef\xbb\xbf'):fail()
    try:
        text=data.decode('utf-8');_check_text_depth(text)
        result=json.loads(text,object_pairs_hook=_unique_object,parse_float=_noninteger,parse_constant=_noninteger)
        _check_json_value(result)
        if encode_canonical(result)!=data:fail()
        return result
    except (ValueError,UnicodeError,RecursionError,CrateError):fail()

def decode_manifest(data,limits=None):
    l=limits or Limits()
    try:
        v=_object(strict_json(data,l.manifest_bytes),{'version','profile','repositories','roots','commits','objects','gitlinks','lfs','payloads','counts'})
        if type(v['version']) is not int or v['version']!=1 or v['profile']!='trusted-local-v1':fail()
        seeds={}
        for r in _array(v['repositories']):
            _object(r,{'id','seeds'});identity=_id(r['id'])
            if identity in seeds:fail()
            selected=_unique([_oid(x) for x in _array(r['seeds'])])
            if not 1<=len(selected)<=l.bundle_seed_refs:fail()
            seeds[identity]=tuple(selected)
        if not 1<=len(seeds)<=l.repositories:fail()
        def repo(x):
            if _id(x) not in seeds:fail()
            return x
        roots=[];ancestors={}
        for r in _array(v['roots']):
            _object(r,{'id','repository','commits','ancestors'});identity=_id(r['id']);repository=repo(r['repository'])
            if identity in ancestors:fail()
            selected=_unique([_oid(x) for x in _array(r['commits'])]);alloids=_unique([_oid(x) for x in _array(r['ancestors'])])
            if not selected or not set(selected)<=set(alloids) or len(alloids)>l.commits:fail()
            roots.append(RootSpec(identity,repository,tuple(selected)));ancestors[identity]=tuple(alloids)
        if not 1<=len(roots)<=l.root_groups or sum(len(r.commits) for r in roots)>l.selected_root_commits:fail()
        commits=[]
        for c in _array(v['commits']):
            _object(c,{'repository','oid','tree','parents'})
            commits.append(CommitRecord(repo(c['repository']),_oid(c['oid']),_oid(c['tree']),tuple(_oid(x) for x in _array(c['parents']))))
        _unique(commits,lambda c:(c.repository,c.oid))
        objects=[]
        for o in _array(v['objects']):
            _object(o,{'repository','oid','kind','size'})
            if o['kind'] not in ('commit','tree','blob'):fail()
            objects.append(ObjectRecord(repo(o['repository']),_oid(o['oid']),o['kind'],_number(o['size'],l.git_object_bytes)))
        _unique(objects,lambda o:(o.repository,o.oid))
        links=[]
        for x in _array(v['gitlinks']):
            _object(x,{'parent_repository','parent_commit','path','name','url_sha256','child_repository','child_commit'})
            if not isinstance(x['name'],str) or not re.fullmatch(r'[A-Za-z0-9._/-]{1,200}',x['name']):fail()
            links.append(GitlinkRecord(repo(x['parent_repository']),_oid(x['parent_commit']),_relative_path(x['path'],l),x['name'],_sha(x['url_sha256']),repo(x['child_repository']),_oid(x['child_commit'])))
        _unique(links,lambda x:(x.parent_repository,x.parent_commit,x.path))
        occurrences=[]
        for x in _array(v['lfs']):
            _object(x,{'repository','commit','path','blob_oid','sha256','size'})
            size=_number(x['size'],l.lfs_payload_bytes)
            if size==0:fail()
            occurrences.append(LfsOccurrence(repo(x['repository']),_oid(x['commit']),_relative_path(x['path'],l),_oid(x['blob_oid']),_sha(x['sha256']),size))
        _unique(occurrences,lambda x:(x.repository,x.commit,x.path))
        if len(commits)>l.commits or len(objects)>l.git_objects or len(links)>l.gitlink_occurrences or len(occurrences)>l.commit_path_visits:fail()
        closure=Closure(tuple(roots),ancestors,seeds,tuple(commits),tuple(objects),tuple(links),tuple(occurrences))
        if encode_manifest(closure)!=data:fail()
        return closure
    except (TypeError,KeyError,ValueError,CrateError):fail()
