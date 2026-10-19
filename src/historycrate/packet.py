"""Self-contained directory packets and fresh native semantic verification."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import time
from types import SimpleNamespace

from .acquire import RepositoryPool,_metadata,_copy_file,recheck_sources
from .closure import build_closure
from .errors import CrateError
from .limits import Budget
from .lfs import collect_payloads,_qualify_clean_roundtrip
from .manifest import encode_manifest,decode_manifest,strict_json,value
from .metadata import read_gitmodules
from .model import AcquiredRepo,Binding,PayloadRecord,PayloadSet,RepoSpec,Spec,VerifiedPacket
from .monitor import CopyMonitor
from .native import NativeAdapter,refuse
from .objects import ObjectReader
from .paths import open_directory,open_regular_beneath,_DIRECTORY_FLAGS,_validate_owned,assert_disjoint,validate_relative_path,_absolute,protected_worktree_root
from .schema import encode_canonical,_object

_SHA=re.compile(r'[0-9a-f]{64}\Z')
_BUNDLE=re.compile(r'repos/[a-z][a-z0-9_-]{0,31}\.bundle\Z')
_LFS=re.compile(r'lfs/objects/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})\Z')


def _phase(job,path):
    """Fresh result/native caches, shared absolute deadline and observed tree."""
    path.mkdir(mode=0o700)
    observed=getattr(job,'observation_root',job.root)
    native=NativeAdapter(path,job.tools,job.limits,observation_root=observed,started=job.native.started)
    native.records=job.native.records
    if not hasattr(job,'controller_observations'):job.controller_observations=[]
    phase=SimpleNamespace(root=path,observation_root=observed,native=native,tools=job.tools,limits=job.limits,
                          budget=Budget(job.limits),source_paths=(),controller_observations=job.controller_observations,external_materialized_bytes=getattr(job,'external_materialized_bytes',0))
    return phase


def _artifact_path(path):
    if path=='manifest.json' or _BUNDLE.fullmatch(path):return
    match=_LFS.fullmatch(path)
    if match and match[1]==match[3][:2] and match[2]==match[3][2:4]:return
    refuse('INVALID_PACKET_LAYOUT',4,path=path)


def _inventory(packet,job):
    """Pin and hash the complete directory; unknown/empty paths fail closed."""
    root=open_directory(packet);records={};dirs={};seen=set();count=0;start=time.monotonic();monitor=CopyMonitor(job)
    def walk(fd,prefix):
        nonlocal count
        before=_metadata(os.fstat(fd));identity=before[:2]
        if identity in seen:refuse('PACKET_ALIAS',4)
        seen.add(identity);dirs[prefix]=before
        with os.scandir(fd) as iterator:
            names=[]
            for item in iterator:
                count+=1
                if count>job.limits.observation_entries:refuse('OBSERVATION_LIMIT',5)
                names.append(item.name)
        for name in sorted(names):
            monitor.check()
            relative=prefix+'/'+name if prefix else name
            validate_relative_path(relative,repository=False)
            info=os.stat(name,dir_fd=fd,follow_symlinks=False);directory=stat.S_ISDIR(info.st_mode)
            _validate_owned(info,directory=directory)
            if directory:
                child=os.open(name,_DIRECTORY_FLAGS,dir_fd=fd)
                try:
                    if _metadata(os.fstat(child))!=_metadata(info):refuse('SOURCE_CHANGED',4)
                    walk(child,relative)
                finally:os.close(child)
            else:
                if relative!='COMPLETE.json':_artifact_path(relative)
                if info.st_size>job.limits.packet_bytes:refuse('BUDGET_EXCEEDED',5,resource='packet_bytes')
                if relative in ('manifest.json','COMPLETE.json') and info.st_size>job.limits.manifest_bytes:refuse('BUDGET_EXCEEDED',5,resource='manifest_bytes')
                source=open_regular_beneath(root,relative)
                try:
                    expected=_metadata(info)
                    if _metadata(os.fstat(source))!=expected:refuse('SOURCE_CHANGED',4)
                    digest=hashlib.sha256();size=0
                    while True:
                        block=os.read(source,1024*1024)
                        if not block:break
                        size+=len(block)
                        if size>info.st_size:refuse('SOURCE_CHANGED',4)
                        digest.update(block);monitor.check()
                    if size!=info.st_size or _metadata(os.fstat(source))!=expected:refuse('SOURCE_CHANGED',4)
                    records[relative]={'size':size,'sha256':digest.hexdigest(),'metadata':expected}
                finally:os.close(source)
                if _metadata(os.stat(name,dir_fd=fd,follow_symlinks=False))!=expected:refuse('SOURCE_CHANGED',4)
        if _metadata(os.fstat(fd))!=before:refuse('SOURCE_CHANGED',4)
    try:
        walk(root,'')
        allowed={'','repos','lfs','lfs/objects'}
        for relative in records:
            parts=relative.split('/')
            allowed.update('/'.join(parts[:n]) for n in range(1,len(parts)))
        if set(dirs)!=allowed:refuse('INVALID_PACKET_LAYOUT',4)
        if sum(r['size'] for r in records.values())>job.limits.packet_bytes:refuse('BUDGET_EXCEEDED',5,resource='packet_bytes')
        reopened=open_directory(packet)
        try:
            if _metadata(os.fstat(reopened))!=dirs['']:refuse('SOURCE_CHANGED',4)
        finally:os.close(reopened)
        return records,dirs
    finally:os.close(root)


def _copy(source,destination,job,maximum):
    monitor=CopyMonitor(job);parent=open_directory(destination.parent)
    try:monitor.allocation(parent,source.stat(follow_symlinks=False).st_size)
    finally:os.close(parent)
    fd=open_directory(source.parent)
    try:return _copy_file(fd,source.name,_metadata(source.stat(follow_symlinks=False)),destination,maximum,monitor)
    finally:os.close(fd)


def _preflight_native(job,objects):
    # Conservative next-write estimate, not a reservation or a hard disk bound.
    estimate=sum(2*x.size+1024 for x in objects)+65536
    fd=open_directory(job.root)
    try:CopyMonitor(job).allocation(fd,estimate)
    finally:os.close(fd)


def _complete(root,closure,job):
    records,_=_inventory(root,job)
    artifacts=[{'path':path,'size':record['size'],'sha256':record['sha256']} for path,record in sorted(records.items())]
    doc={'version':1,'profile':'trusted-local-v1','manifest_sha256':records['manifest.json']['sha256'],'artifacts':artifacts}
    raw=encode_canonical(doc)
    if len(raw)>job.limits.manifest_bytes:refuse('BUDGET_EXCEEDED',5,resource='manifest_bytes')
    (root/'COMPLETE.json').write_bytes(raw);(root/'COMPLETE.json').chmod(0o600)
    _inventory(root,job)


def build_packet(spec,job):
    """Build owned private artifacts; no output publication and no cached verify."""
    pool=RepositoryPool(spec,job);closure=build_closure(spec,pool,job)
    payloads=collect_payloads(closure,spec.repositories,job)
    root=job.root/('packet-build-'+secrets.token_hex(6));root.mkdir(mode=0o700)
    (root/'repos').mkdir(mode=0o700);(root/'lfs/objects').mkdir(mode=0o700,parents=True)
    raw=encode_manifest(closure)
    if len(raw)>job.limits.manifest_bytes:refuse('BUDGET_EXCEEDED',5,resource='manifest_bytes')
    (root/'manifest.json').write_bytes(raw);(root/'manifest.json').chmod(0o600)
    for repository,seeds in closure.seeds.items():
        job.native.run('install_seeds',{'repo':repository,'oids':seeds})
        _preflight_native(job,(x for x in closure.objects if x.repository==repository))
        job.native.run('bundle_selected',{'repo':repository,'name':repository,'oids':seeds})
        _copy(job.root/'artifacts'/f'{repository}.bundle',root/'repos'/f'{repository}.bundle',job,job.limits.packet_bytes)
    for payload in payloads.records:
        dest=root/'lfs/objects'/payload.sha256[:2]/payload.sha256[2:4]/payload.sha256
        dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        _copy(payload.private_path,dest,job,job.limits.lfs_payload_bytes)
    _complete(root,closure,job)
    recheck_sources(job)
    return root,closure


def _header(bundle,seeds,job):
    expected={f'{oid} refs/historycrate/commits/{oid}'.encode() for oid in seeds};actual=set()
    with bundle.open('rb') as f:
        if f.readline(32)!=b'# v2 git bundle\n':refuse('INVALID_BUNDLE_HEADER',4)
        for _ in range(job.limits.bundle_seed_refs+1):
            line=f.readline(160)
            if line==b'\n':break
            if not line.endswith(b'\n') or line[:-1] not in expected or line[:-1] in actual:refuse('INVALID_BUNDLE_REFS',4)
            actual.add(line[:-1])
        else:refuse('INVALID_BUNDLE_HEADER',4)
        if actual!=expected or f.read(4)!=b'PACK':refuse('INVALID_BUNDLE_HEADER',4)


def _validate_complete(snapshot,closure,records,job):
    try:
        complete=_object(strict_json((snapshot/'COMPLETE.json').read_bytes(),job.limits.manifest_bytes),{'version','profile','manifest_sha256','artifacts'})
        if type(complete['version']) is not int or complete['version']!=1 or complete['profile']!='trusted-local-v1':refuse('INVALID_COMPLETE',4)
        expected={'manifest.json',*(f'repos/{r}.bundle' for r in closure.seeds)}
        expected.update(f'lfs/objects/{x["sha256"][:2]}/{x["sha256"][2:4]}/{x["sha256"]}' for x in value(closure)['payloads'])
        if set(records)!=expected|{'COMPLETE.json'}:refuse('INVALID_PACKET_LAYOUT',4)
        artifacts=[{'path':p,'size':records[p]['size'],'sha256':records[p]['sha256']} for p in sorted(expected)]
        if encode_canonical(complete)!=encode_canonical({'version':1,'profile':'trusted-local-v1','manifest_sha256':records['manifest.json']['sha256'],'artifacts':artifacts}):refuse('PACKET_HASH_MISMATCH',4)
    except (KeyError,TypeError):refuse('INVALID_COMPLETE',4)
    except CrateError as exc:
        if exc.exit_code==2:refuse('INVALID_COMPLETE',4)
        raise


def verify_packet(packet,job):
    packet=Path(packet)
    if not packet.is_absolute():refuse('INVALID_PACKET_PATH',2)
    internal=packet==job.root or job.root in packet.parents
    if not internal:
        assert_disjoint((packet,job.root))
        job._packet_source_paths=tuple(dict.fromkeys((*getattr(job,'_packet_source_paths',()),packet)))
        packet_fd=open_directory(packet)
        try:
            info=os.fstat(packet_fd);identity=(info.st_dev,info.st_ino)
            for tool in (job.tools.git,job.tools.git_lfs,job.tools.git_exec_path):
                for parent in (tool,*tool.parents):
                    observed=parent.stat(follow_symlinks=False)
                    if identity==(observed.st_dev,observed.st_ino):refuse('SOURCE_PATH_CANNOT_BE_TOOL')
        finally:os.close(packet_fd)
    before,dirs=_inventory(packet,job)
    if not {'manifest.json','COMPLETE.json'}<=before.keys():refuse('INCOMPLETE_PACKET',4)
    private=job.root/('packet-verify-'+secrets.token_hex(6));private.mkdir(mode=0o700)
    snapshot=private/'packet';snapshot.mkdir(mode=0o700)
    for d in sorted(set(dirs)-{''},key=lambda x:(x.count('/'),x)):(snapshot/d).mkdir(mode=0o700)
    root_fd=open_directory(packet);monitor=CopyMonitor(job)
    try:
        destination_fd=open_directory(snapshot)
        try:monitor.allocation(destination_fd,sum(x['size'] for x in before.values()))
        finally:os.close(destination_fd)
        for relative,record in sorted(before.items()):
            digest=_copy_file(root_fd,relative,record['metadata'],snapshot/relative,job.limits.packet_bytes,monitor)
            if digest!=record['sha256']:refuse('SOURCE_CHANGED',4)
    finally:os.close(root_fd)
    if _inventory(packet,job)!=(before,dirs):refuse('SOURCE_CHANGED',4)
    declared=decode_manifest((snapshot/'manifest.json').read_bytes(),job.limits)
    _validate_complete(snapshot,declared,before,job)
    phase=_phase(job,private/'imported');acquired={};readers={}
    for repository,seeds in declared.seeds.items():
        bundle=snapshot/'repos'/f'{repository}.bundle';_header(bundle,seeds,job)
        phase.budget.charge('repositories',1)
        phase.native.run('init',{'name':repository,'bare':True})
        _copy(bundle,phase.root/'artifacts'/f'{repository}.bundle',phase,job.limits.packet_bytes)
        _preflight_native(phase,(x for x in declared.objects if x.repository==repository))
        phase.native.run('unbundle',{'repo':repository,'name':repository})
        phase.native.run('install_seeds',{'repo':repository,'oids':seeds})
        phase.native.run('fsck',{'repo':repository})
        actual=phase.native.run('list_objects',{'repo':repository}).stdout
        expected=b''.join(f'{x.oid} {x.kind} {x.size}\n'.encode() for x in sorted(declared.objects,key=lambda x:x.oid) if x.repository==repository)
        if sorted(actual.splitlines())!=sorted(expected.splitlines()):refuse('PACKET_OBJECT_SET_MISMATCH',4)
        acquired[repository]=AcquiredRepo(repository,phase.native._repo(repository),'packet')
        readers[repository]=ObjectReader(acquired[repository],phase)
    # Literal URLs are obtained from actual committed .gitmodules, then matched
    # against declared digested identities. They never become a network target.
    bindings={}
    for link in declared.gitlinks:
        metadata=read_gitmodules(readers[link.parent_repository],link.parent_commit)
        if link.path not in metadata:refuse('PACKET_MAPPING_MISMATCH',4)
        name,url=metadata[link.path]
        if name!=link.name or hashlib.sha256(url.encode()).hexdigest()!=link.url_sha256:refuse('PACKET_MAPPING_MISMATCH',4)
        key=(link.parent_repository,link.path,url)
        if bindings.setdefault(key,link.child_repository)!=link.child_repository:refuse('PACKET_MAPPING_MISMATCH',4)
    spec=Spec(1,tuple(RepoSpec(r,a.stage_git_dir,snapshot/'lfs/objects') for r,a in sorted(acquired.items())),declared.roots,tuple(Binding(*key,child) for key,child in sorted(bindings.items())),job.limits)
    pool=SimpleNamespace(get=lambda name:acquired[name])
    # These readers and all conversion/result caches are distinct from construction.
    actual=build_closure(spec,pool,phase)
    if encode_manifest(actual)!=encode_manifest(declared):refuse('PACKET_SEMANTIC_MISMATCH',4)
    payloads=[]
    for item in value(actual)['payloads']:
        digest=item['sha256'];path=snapshot/'lfs/objects'/digest[:2]/digest[2:4]/digest
        relative=path.relative_to(snapshot).as_posix();record=before[relative]
        if record['sha256']!=digest or record['size']!=item['size']:refuse('LFS_HASH_MISMATCH',4)
        phase.budget.charge('unique_lfs_bytes',item['size'])
        payload=PayloadRecord(digest,item['size'],path);_qualify_clean_roundtrip(payload,phase);payloads.append(payload)
    # Rehash original bytes after all native work; any changing source blocks.
    if _inventory(packet,job)!=(before,dirs):refuse('SOURCE_CHANGED',4)
    def recheck_original():
        try:
            if _inventory(packet,job)!=(before,dirs):refuse('SOURCE_CHANGED',4)
        except CrateError as exc:
            if exc.exit_code==5:raise
            refuse('SOURCE_CHANGED',4)
    job._prepublication_checks=tuple(getattr(job,'_prepublication_checks',()))+(recheck_original,)
    return VerifiedPacket(private,actual,PayloadSet(tuple(payloads)),hashlib.sha256((snapshot/'COMPLETE.json').read_bytes()).hexdigest())


def validate_selection_output(spec,output):
    """Protect every declared source role lexically without opening unused data.

    Publication separately pins and checks inode relationships for demanded
    inputs. This check also protects nonexistent declared .git/cache endpoints.
    """
    destination=_absolute(output)
    for repo in spec.repositories:
        for source in (repo.git_dir,repo.lfs_objects_dir,protected_worktree_root(repo.git_dir)):
            if source is not None and (source==destination or source in destination.parents or destination in source.parents):
                refuse('PATH_OVERLAP',3)
    return destination


def create_packet(spec,output,job):
    from .publication import publish_tree, publication_checkpoint, publication_status
    from .reports import selection_warnings
    output=validate_selection_output(spec,output)
    staged,closure=build_packet(spec,job)
    verified=verify_packet(staged,job)
    warnings=selection_warnings(spec,verified.closure,job.limits)
    recheck_sources(job)
    job._prepublication_checks=tuple(getattr(job,'_prepublication_checks',()))+(lambda:recheck_sources(job),)
    checkpoint=publication_checkpoint(job)
    try:
        publication=publish_tree(verified.private_root/'packet',output,job,job.limits.packet_bytes)
        return {'publication':publication.publication,'counts':value(verified.closure)['counts'],'structural_checks':['artifact-hashes','native-fsck','exact-bundle-object-sets','recomputed-historical-closure','required-lfs-bytes'],'rehearsed':[],'warnings':warnings}
    except BaseException as exc:
        if publication_status(job,since=checkpoint)!='not-published' or getattr(exc,'context',{}).get('publication')=='published-durability-uncertain':
            raise CrateError('PUBLISHED_DURABILITY_UNCERTAIN',6,{'publication':'published-durability-uncertain'}) from exc
        raise
