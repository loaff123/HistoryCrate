"""Complete selected ancestry and exact historical local gitlink bindings."""
from __future__ import annotations

from collections import defaultdict, deque
import hashlib
import time
from .errors import CrateError
from .limits import Budget
from .metadata import attributes_at,read_gitmodules,verify_conversion,walk_tree
from .model import Closure,GitlinkRecord,LfsOccurrence
from .native import refuse
from .objects import ObjectReader


class _GraphGuard:
    """Incremental longest-path admission; do not scan unrelated commits per edge."""
    def __init__(self,limit,checkpoint):
        self.limit=limit;self.checkpoint=checkpoint;self.edges=defaultdict(set);self.depths={}
    def add(self,parent,child):
        self.checkpoint()
        if child in self.edges[parent]:return
        # A back edge can only exist when the prospective parent is already at
        # least as deep as the child. Inspect only this child's descendants.
        if self.depths.get(parent,0)>=self.depths.get(child,0):
            pending=[child];seen=set()
            while pending:
                self.checkpoint();node=pending.pop()
                if node==parent:refuse('RECURSIVE_GITLINK_CYCLE',3,repository=parent[0],commit=parent[1])
                if node not in seen:seen.add(node);pending.extend(self.edges[node])
        self.edges[parent].add(child)
        pending=deque([(child,self.depths.get(parent,0)+1)])
        while pending:
            self.checkpoint();node,depth=pending.popleft()
            if depth>self.limit:refuse('BUDGET_EXCEEDED',5,resource='repository_depth')
            if depth>self.depths.get(node,0):
                self.depths[node]=depth
                pending.extend((next_node,depth+1) for next_node in self.edges[node])


def _check_materialization_graph(commits,links,limit,checkpoint=lambda:None):
    """Only gitlink edges consume nesting depth; ancestry is a separate relation."""
    edges=defaultdict(list)
    for link in links:edges[(link.parent_repository,link.parent_commit)].append((link.child_repository,link.child_commit))
    maximum={}
    for vertex in commits:
        checkpoint()
        stack=[(vertex,False)];active=set()
        while stack:
            checkpoint()
            node,leaving=stack.pop()
            if leaving:
                active.remove(node)
                maximum[node]=max((1+maximum[c] for c in edges[node]),default=0)
                if maximum[node]>limit:refuse('BUDGET_EXCEEDED',5,resource='repository_depth')
            elif node in active:refuse('RECURSIVE_GITLINK_CYCLE',3,repository=node[0],commit=node[1])
            elif node not in maximum:
                active.add(node);stack.append((node,True))
                if len(active)-1>limit:refuse('BUDGET_EXCEEDED',5,resource='repository_depth')
                for child in edges[node]:stack.append((child,False))


def build_closure(spec,pool,job):
    from .lfs import parse_lfs_blob
    readers={};commits={};seeds=defaultdict(set);seed_budgets={};links=[];occurrences=[];queue=deque();queued=set()
    bindings={(b.parent_repository,b.path,b.url):b.child_repository for b in spec.bindings}
    def checkpoint():
        if time.monotonic()-job.native.started>job.limits.job_wall_seconds:refuse('BUDGET_EXCEEDED',5,resource='job_wall_seconds')
    guard=_GraphGuard(job.limits.repository_depth,checkpoint)
    def demand(repository,oid,kind,seed=False):
        if seed and oid not in seeds[repository]:
            seed_budgets.setdefault(repository,Budget(job.limits)).charge('bundle_seed_refs',1);seeds[repository].add(oid)
        key=(repository,oid)
        if key not in queued:queued.add(key);queue.append((repository,oid,kind))
    job.budget.charge('root_groups',len(spec.roots));job.budget.charge('selected_root_commits',sum(len(r.commits) for r in spec.roots))
    for root in spec.roots:
        for oid in root.commits:demand(root.repository,oid,'commit',True)
    while queue:
        if time.monotonic()-job.native.started>job.limits.job_wall_seconds:refuse('BUDGET_EXCEEDED',5,resource='job_wall_seconds')
        repository,oid,reason=queue.popleft()
        reader=readers.get(repository)
        if reader is None:reader=readers[repository]=ObjectReader(pool.get(repository),job)
        try:commit=reader.commit(oid)
        except CrateError as exc:
            if exc.code=='MISSING_COMMIT' and reason in ('parent','child'):refuse('MISSING_'+reason.upper()+'_COMMIT',4,repository=repository,commit=oid)
            raise
        job.budget.charge('commits',1);commits[(repository,oid)]=commit
        for parent in commit.parents:demand(repository,parent,'parent')
        files=walk_tree(reader,oid,job)
        ordinary=tuple(sorted(path for path,e in files.items() if e.mode!=0o160000))
        # Size/type qualification precedes invoking native attribute parsers.
        for path in ordinary:
            info=reader.info(files[path].oid)
            if info.kind!='blob':refuse('EXPECTED_BLOB',4,repository=repository,commit=oid,path=path)
            leaf=path.rsplit('/',1)[-1]
            resource='gitattributes_bytes' if leaf=='.gitattributes' else 'gitmodules_bytes' if leaf=='.gitmodules' else None
            if resource and info.size>getattr(job.limits,resource):refuse('BUDGET_EXCEEDED',5,resource=resource)
        attrs=attributes_at(reader,oid,ordinary)
        for path in ordinary:
            entry=files[path];values=attrs[path];info=reader.info(entry.oid)
            if path.rsplit('/',1)[-1] in ('.gitmodules','.gitattributes') and values['filter']=='lfs':refuse('LFS_METADATA_REFUSED',3,commit=oid,path=path)
            if values['filter']=='lfs' and info.size:
                if info.size>job.limits.pointer_bytes:refuse('BUDGET_EXCEEDED',5,resource='pointer_bytes')
                _,raw=reader.read(entry.oid);pointer=parse_lfs_blob(raw,values)
                if pointer is None:refuse('INTERNAL_INVARIANT',6)
                sha,size=pointer
                if size>job.limits.lfs_payload_bytes:refuse('BUDGET_EXCEEDED',5,resource='lfs_payload_bytes')
                occurrences.append(LfsOccurrence(repository,oid,path,entry.oid,sha,size))
            else:verify_conversion(reader,oid,path,entry.oid,values,job)
        metadata=read_gitmodules(reader,oid)
        for path,entry in sorted(files.items()):
            if entry.mode!=0o160000:continue
            job.budget.charge('gitlink_occurrences',1)
            if path not in metadata:refuse('MISSING_GITMODULES',4,repository=repository,commit=oid,path=path)
            name,url=metadata[path];url_sha=hashlib.sha256(url.encode()).hexdigest()
            child=bindings.get((repository,path,url))
            if child is None:refuse('MISSING_BINDING',4,repository=repository,commit=oid,path=path,url_sha256=url_sha)
            links.append(GitlinkRecord(repository,oid,path,name,url_sha,child,entry.oid))
            # Refuse an edge before acquiring its child, rather than waiting for
            # the entire graph. Shared previously acquired nodes stay valid.
            guard.add((repository,oid),(child,entry.oid))
            demand(child,entry.oid,'child',True)
    _check_materialization_graph(commits,links,job.limits.repository_depth,checkpoint)
    root_ancestors={}
    for root in spec.roots:
        ancestors=set();pending=list(root.commits)
        while pending:
            checkpoint();oid=pending.pop()
            if oid in ancestors:continue
            ancestors.add(oid);pending.extend(commits[(root.repository,oid)].parents)
        root_ancestors[root.id]=tuple(sorted(ancestors))
    objects=tuple(sorted((record for reader in readers.values() for record in reader.records.values()),key=lambda x:(x.repository,x.oid)))
    return Closure(tuple(spec.roots),root_ancestors,{k:tuple(sorted(v)) for k,v in sorted(seeds.items())},
                   tuple(commits[k] for k in sorted(commits)),objects,
                   tuple(sorted(links,key=lambda x:(x.parent_repository,x.parent_commit,x.path))),
                   tuple(sorted(occurrences,key=lambda x:(x.repository,x.commit,x.path))))


def explain_inclusion(closure,repository,commit,path=None):
    included={(c.repository,c.oid):c for c in closure.commits}
    if (repository,commit) not in included:refuse('COMMIT_NOT_INCLUDED',4,repository=repository,commit=commit)
    reasons=[]
    for root in closure.roots:
        if root.repository==repository and commit in root.commits:reasons.append({'kind':'selected-root','root':root.id})
    for record in closure.commits:
        if record.repository==repository and commit in record.parents:reasons.append({'kind':'parent','repository':repository,'commit':record.oid})
    for link in closure.gitlinks:
        if link.child_repository==repository and link.child_commit==commit:
            reasons.append({'kind':'gitlink','repository':link.parent_repository,'commit':link.parent_commit,'path':link.path,'url_sha256':link.url_sha256})
    result={'repository':repository,'commit':commit,'reasons':reasons,'root_groups':sorted(root.id for root in closure.roots if root.repository==repository and commit in closure.root_ancestors[root.id])}
    if path is not None:
        result['path']=path
        result['lfs']=[{'sha256':x.sha256,'size':x.size,'blob_oid':x.blob_oid} for x in closure.lfs if (x.repository,x.commit,x.path)==(repository,commit,path)]
    return result
