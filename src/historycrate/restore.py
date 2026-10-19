"""Fresh, original-identity recursive restores of verified private packets.

Only fixed native operations touch owned scratch. Publication is a separate
controller-only copy/commit after native postconditions and input rechecks.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import stat
from types import SimpleNamespace

from .acquire import recheck_sources
from .errors import CrateError
from .lfs import hydrate_file, _copy_verified, _signature
from .metadata import walk_tree, read_gitmodules
from .model import AcquiredRepo, RestoreResult, VerifiedPacket
from .monitor import CopyMonitor
from .native import _config, _name, _oid, refuse
from .objects import ObjectReader
from .packet import _phase, _copy, _inventory, _preflight_native, _validate_complete
from .paths import open_directory, open_regular_beneath, _validate_owned
from .publication import publish_tree, publication_checkpoint, publication_status


def _fail(**context):
    refuse('RESTORE_POSTCONDITION_FAILED', 4, **context)


def _reader(job, alias):
    return ObjectReader(AcquiredRepo(alias, job.native._repo(alias), 'verified-packet'), job)


def _links(closure, repository, commit, files):
    links={link.path:link for link in closure.gitlinks
           if (link.parent_repository,link.parent_commit)==(repository,commit)}
    actual={path:entry.oid for path,entry in files.items() if entry.mode==0o160000}
    if actual!={path:link.child_commit for path,link in links.items()}:
        _fail(check='gitlink-tree')
    return links


def _check_config(alias, links, job):
    expected={key.lower():[value] for key,value in _config(job.tools).items()}
    expected.update({'core.repositoryformatversion':['0'],'core.bare':['false'],
                     'core.logallrefupdates':['true']})
    for path,link in links.items():
        for key,value in {'path':path,'url':'historycrate-offline:'+link.child_repository,
                          'active':'true','update':'none','ignore':'none'}.items():
            expected['submodule.'+link.name+'.'+key]=[value]
    raw=job.native.run('config_list',{'repo':alias})
    if raw.stderr:_fail(check='owned-config')
    observed={}
    try:
        for item in raw.stdout.split(b'\0'):
            if not item:continue
            key,value=item.decode('utf-8').split('\n',1)
            observed.setdefault(key,[]).append(value)
    except (ValueError,UnicodeError):_fail(check='owned-config')
    if observed.get('lfs.repositoryformatversion')==['0']:
        expected['lfs.repositoryformatversion']=['0']
    if set(observed)!=set(expected) or any(set(values)!=set(expected[key]) for key,values in observed.items()):
        _fail(check='owned-config')


def _worktree_inventory(root, files, job):
    """Refuse even ignored or empty extra worktree paths, links and aliases."""
    wanted=set(files)
    for path in files:
        parts=path.split('/')
        wanted.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    found=set();seen=set();monitor=CopyMonitor(job)
    def visit(path,prefix):
        fd=open_directory(path)
        try:
            entries=os.listdir(fd)
            if len(found)+len(entries)>job.limits.observation_entries:
                refuse('OBSERVATION_LIMIT',5)
            for name in entries:
                if not prefix and name=='.git':continue
                relative=prefix+name
                if relative not in wanted:_fail(check='extra-worktree-path',path=relative)
                info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                directory=stat.S_ISDIR(info.st_mode);_validate_owned(info,directory=directory)
                identity=(info.st_dev,info.st_ino)
                if identity in seen:_fail(check='worktree-alias')
                seen.add(identity);found.add(relative)
                entry=files.get(relative)
                if entry is not None:
                    if entry.mode==0o160000:
                        if not directory:_fail(check='gitlink-directory',path=relative)
                    elif directory or stat.S_IMODE(info.st_mode)!=(entry.mode&0o777):
                        _fail(check='worktree-mode',path=relative)
                elif not directory:_fail(check='tree-directory',path=relative)
                if directory and (entry is None or entry.mode!=0o160000):visit(path/name,relative+'/')
                monitor.check()
        finally:os.close(fd)
    visit(root,'')
    if wanted!=found:_fail(check='missing-worktree-path')


def _check_payload(path, occurrence, job):
    parent=open_directory(path.parent)
    try:
        source=open_regular_beneath(parent,path.name)
        try:_copy_verified(source,None,occurrence.sha256,occurrence.size,job,CopyMonitor(job))
        finally:os.close(source)
    finally:os.close(parent)


def _fingerprint(path, job):
    parent=open_directory(path.parent)
    source=None
    try:
        source=open_regular_beneath(parent,path.name)
        before=_signature(os.fstat(source));digest=hashlib.sha256();size=0
        maximum=min(2*job.limits.git_object_bytes,job.limits.scratch_bytes,job.limits.command_file_bytes)
        if before[2]>maximum:refuse('BUDGET_EXCEEDED',5,resource='converted_file_bytes')
        monitor=CopyMonitor(job)
        while True:
            block=os.read(source,1024*1024)
            if not block:break
            size+=len(block)
            if size>before[2]:refuse('SOURCE_CHANGED',4)
            digest.update(block);monitor.check()
        if size!=before[2] or _signature(os.fstat(source))!=before:refuse('SOURCE_CHANGED',4)
        return size,digest.hexdigest()
    finally:
        if source is not None:os.close(source)
        os.close(parent)


def _check_conversion_bytes(alias, commit, filename, entry, path, job):
    artifact=job.root/'artifacts/restore-conversion'
    reader=_reader(job,alias)
    fd=open_directory(artifact.parent)
    try:CopyMonitor(job).allocation(fd,2*reader.info(entry.oid).size)
    finally:os.close(fd)
    try:
        job.native.run('conversion_checkout',{'repo':alias,'commit':commit,'path':filename,
                                             'oid':entry.oid,'name':artifact.name})
        if _fingerprint(artifact,job)!=_fingerprint(path/filename,job):
            _fail(check='converted-worktree-bytes',path=filename)
    finally:
        if artifact.exists():artifact.unlink()


def _check_submodule_status(raw, expected):
    # Supported paths contain no controls/newlines. Native output has a fixed
    # status/OID prefix and optionally a describe suffix, not shell quoting.
    unmatched=dict(expected)
    for line in raw.splitlines():
        candidates=[]
        for path,oid in unmatched.items():
            prefix=(' '+oid+' '+path).encode()
            if line==prefix or (line.startswith(prefix+b' (') and line.endswith(b')')):
                candidates.append(path)
        if len(candidates)!=1:_fail(check='recursive-submodule-status')
        del unmatched[candidates[0]]
    if unmatched:_fail(check='recursive-submodule-status')


def check_restored_tree(root, expected, root_id, commit, job):
    """Re-derive native postconditions without trusting the materializer's index."""
    selected=next((item for item in expected.roots if item.id==root_id),None)
    if selected is None or commit not in expected.root_ancestors.get(root_id,()):
        refuse('RESTORE_COMMIT_NOT_ALLOWED',3)
    aliases={path:name for name,(path,bare,identity) in job.native.repositories.items() if not bare}
    pending=[(Path(root),selected.repository,commit,'')];all_links={}
    payloads={(x.repository,x.commit,x.path):x for x in expected.lfs}
    nodes=[]
    while pending:
        path,repository,oid,relative=pending.pop()
        alias=aliases.get(path)
        if alias is None:_fail(check='unregistered-repository')
        gitdir=open_directory(path/'.git');os.close(gitdir)
        reader=_reader(job,alias);files=walk_tree(reader,oid,job)
        links=_links(expected,repository,oid,files)
        _check_config(alias,links,job)
        head=job.native.run('head',{'repo':alias})
        symbolic=job.native.run('head_symbolic',{'repo':alias})
        if head.stdout!=(oid+'\n').encode() or head.stderr or symbolic.returncode!=1 or symbolic.stdout or symbolic.stderr:
            _fail(check='detached-head')
        job.native.run('fsck',{'repo':alias})
        raw=job.native.run('index',{'repo':alias})
        index={}
        try:
            for item in raw.stdout.split(b'\0'):
                if not item:continue
                header,name=item.split(b'\t',1);flag,mode,blob,stage=header.split(b' ')
                name=name.decode('utf-8')
                if flag!=b'H' or stage!=b'0' or name in index:_fail(check='index-flags')
                index[name]=(int(mode,8),blob.decode('ascii'))
        except (ValueError,UnicodeError):_fail(check='index-frame')
        if raw.stderr or index!={p:(e.mode,e.oid) for p,e in files.items()}:_fail(check='exact-index')
        _worktree_inventory(path,files,job)
        for filename,entry in sorted(files.items()):
            if entry.mode==0o160000:continue
            occurrence=payloads.get((repository,oid,filename))
            if occurrence is not None:
                if occurrence.blob_oid!=entry.oid:_fail(check='lfs-blob')
                _check_payload(path/filename,occurrence,job)
                cache=path/'.git/lfs/objects'/occurrence.sha256[:2]/occurrence.sha256[2:4]/occurrence.sha256
                _check_payload(cache,occurrence,job)
                if stat.S_IMODE(cache.stat(follow_symlinks=False).st_mode)!=0o644:_fail(check='lfs-cache-mode')
            # Unconditional path-aware native clean/hash; no reliance on index
            # stat-cache timestamps, status or assumed byte equality for CRLF.
            hashed=job.native.run('hash_path',{'repo':alias,'path':filename})
            if hashed.stdout!=(entry.oid+'\n').encode() or hashed.stderr:_fail(check='clean-hash',path=filename)
            if occurrence is None:_check_conversion_bytes(alias,oid,filename,entry,path,job)
        for filename,link in links.items():
            child_relative=(relative+'/' if relative else '')+filename
            all_links[child_relative]=link.child_commit
            pending.append((path/filename,link.child_repository,link.child_commit,child_relative))
        nodes.append(alias)
    raw=job.native.run('submodule_status',{'repo':aliases[Path(root)]})
    if raw.stderr:_fail(check='recursive-submodule-status')
    _check_submodule_status(raw.stdout,all_links)
    for alias in nodes:
        for operation in ('diff_index','diff_worktree','status'):
            result=job.native.run(operation,{'repo':alias})
            if result.stdout or result.stderr:_fail(check=operation)
    return ('exact-detached-heads','native-fsck','exact-index-no-hidden-flags',
            'recursive-native-submodule-status','native-clean-hash-all-tracked-files',
            'verified-lfs-worktree-and-cache','exact-native-checkout-bytes','exact-worktree-files-and-modes',
            'owned-persistent-configuration','native-clean-status')


def restore_verified(packet: VerifiedPacket, root_id, commit, output, job):
    _name(root_id);_oid(commit)
    if not isinstance(packet,VerifiedPacket):refuse('INVALID_VERIFIED_PACKET',2)
    closure=packet.closure
    selected=next((item for item in closure.roots if item.id==root_id),None)
    if selected is None or commit not in closure.root_ancestors.get(root_id,()):
        refuse('RESTORE_COMMIT_NOT_ALLOWED',3)
    for check in tuple(getattr(job,'_prepublication_checks',())):check()
    snapshot=packet.private_root/'packet'
    # Bind the verified semantic result to these still-private artifact bytes.
    before=_inventory(snapshot,job)
    _validate_complete(snapshot,closure,before[0],job)
    if hashlib.sha256((snapshot/'COMPLETE.json').read_bytes()).hexdigest()!=packet.artifact_digest:
        refuse('PACKET_HASH_MISMATCH',4)
    def input_guard():
        if _inventory(snapshot,job)!=before:refuse('SOURCE_CHANGED',4)
        recheck_sources(job)
    input_guard()
    phase=_phase(job,job.root/('restore-'+secrets.token_hex(6)))
    # Hydration requires the common owning root because payloads live in the
    # verified packet namespace, alongside (not beneath) this fresh phase.
    io_job=SimpleNamespace(**{**vars(phase),'root':job.root,'source_paths':job.source_paths})
    payloads={x.sha256:x for x in packet.payloads.records}
    occurrences={(x.repository,x.commit,x.path):x for x in closure.lfs}
    serial=0
    def materialize(repository,oid,parent=None,subpath=None):
        nonlocal serial
        serial+=1;alias='restore'+str(serial)
        if serial>job.limits.gitlink_occurrences+1:refuse('BUDGET_EXCEEDED',5,resource='gitlink_occurrences')
        objects=[x for x in closure.objects if x.repository==repository]
        _preflight_native(phase,objects)
        if parent is None:phase.native.run('init',{'name':alias,'bare':False})
        else:
            target=phase.native._repo(parent)/subpath
            target.mkdir(mode=0o700,parents=True,exist_ok=True)
            phase.native.run('init_child',{'name':alias,'parent':parent,'path':subpath})
        path=phase.native._repo(alias)
        _copy(snapshot/'repos'/f'{repository}.bundle',phase.root/'artifacts'/f'{alias}.bundle',phase,job.limits.packet_bytes)
        phase.native.run('unbundle',{'repo':alias,'name':alias})
        phase.native.run('install_seeds',{'repo':alias,'oids':closure.seeds[repository]})
        phase.native.run('detach_head',{'repo':alias,'oid':oid})
        reader=_reader(phase,alias);files=walk_tree(reader,oid,phase)
        links=_links(closure,repository,oid,files)
        # This packet was fully qualified before checkout. Read current metadata
        # again solely to prove the controlled local registration matches it.
        metadata=read_gitmodules(reader,oid)
        for filename,link in links.items():
            if filename not in metadata or metadata[filename][0]!=link.name:_fail(check='gitmodule-name')
            phase.native.run('register_submodule',{'repo':alias,'name':link.name,'path':filename,'child':link.child_repository})
        phase.native.run('read_tree',{'repo':alias,'commit':oid})
        phase.native.run('checkout_index',{'repo':alias})
        for filename,entry in sorted(files.items()):
            occurrence=occurrences.get((repository,oid,filename))
            if occurrence is not None:
                payload=payloads.get(occurrence.sha256)
                if payload is None or payload.size!=occurrence.size:_fail(check='missing-payload')
                parent_fd=open_directory((path/filename).parent)
                try:hydrate_file(parent_fd,Path(filename).name,entry.mode,payload,io_job)
                finally:os.close(parent_fd)
                cache=path/'.git/lfs/objects'/payload.sha256[:2]/payload.sha256[2:4]/payload.sha256
                if not cache.exists():
                    cache.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    parent_fd=open_directory(cache.parent)
                    try:hydrate_file(parent_fd,cache.name,0o100644,payload,io_job)
                    finally:os.close(parent_fd)
        for filename,link in sorted(links.items()):materialize(link.child_repository,link.child_commit,alias,filename)
        return path
    root=materialize(selected.repository,commit)
    checks=check_restored_tree(root,closure,root_id,commit,phase)
    input_guard()
    # Rehearsals also establish the complete output-byte threshold, including
    # objects, indexes and every embedded child repository/cache.
    from .publication import _inventory as output_inventory
    fd=open_directory(root)
    try:output_inventory(fd,phase,CopyMonitor(phase),job.limits.restore_bytes)
    finally:os.close(fd)
    old_checks=tuple(getattr(job,'_prepublication_checks',()))
    job._prepublication_checks=old_checks+(input_guard,)
    checkpoint=publication_checkpoint(job)
    try:
        try:
            if output is not None:
                publish_tree(root,Path(output),job,job.limits.restore_bytes)
            else:
                for check in job._prepublication_checks:check()
            return RestoreResult(root_id,commit,Path(output) if output is not None else None,checks)
        finally:job._prepublication_checks=old_checks
    except BaseException as exc:
        if publication_status(job,since=checkpoint)!='not-published' or getattr(exc,'context',{}).get('publication')=='published-durability-uncertain':
            raise CrateError('PUBLISHED_DURABILITY_UNCERTAIN',6,
                             {'publication':'published-durability-uncertain'}) from exc
        raise
