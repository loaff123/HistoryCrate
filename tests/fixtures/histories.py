"""Original MIT fixtures. Builders declare history; they do not import product traversal."""
import hashlib
import os
from pathlib import Path
import subprocess

from tests.toolchain import GIT as TEST_GIT
GIT=str(TEST_GIT)

def native(repo, *args, data=b''):
    env={'PATH':str(TEST_GIT.parent)+':/usr/bin:/bin','HOME':str(repo.parent),'LC_ALL':'C','TZ':'UTC',
         'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_ATTR_NOSYSTEM':'1',
         'GIT_AUTHOR_NAME':'Original Fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid',
         'GIT_COMMITTER_NAME':'Original Fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid',
         'GIT_AUTHOR_DATE':'2026-01-01T00:00:00Z','GIT_COMMITTER_DATE':'2026-01-01T00:00:00Z',
         'GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'}
    return subprocess.run([GIT,'--no-pager','-c','core.hooksPath=/dev/null',*args],cwd=repo,env=env,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout

class HistoryBuilder:
    def __init__(self, root):
        self.root=Path(root); self.repos={}; self.commits={}; self.sequence=0
    def repository(self,name):
        path=self.root/(name+'.git'); path.mkdir(mode=0o700)
        native(path,'init','--bare','--quiet','--object-format=sha1','--initial-branch=main','--template=')
        self.repos[name]=path; self.commits[name]={}
        return path
    def blob(self,repo,data):
        return native(self.repos[repo],'hash-object','-w','--stdin',data=data).strip().decode()
    def commit(self,repo,files,parents=(),label=None,update=True):
        nodes={}
        for path,value in files.items():
            parts=path.split('/'); node=nodes
            for component in parts[:-1]:node=node.setdefault(component,{})
            node[parts[-1]]=value
        def tree(node):
            entries=[]
            for name,value in node.items():
                if isinstance(value,dict):mode,oid='040000',tree(value); kind='tree'
                elif isinstance(value,tuple):mode,oid=value; mode=f'{mode:o}'; kind='commit' if mode=='160000' else 'blob'
                else:mode,oid,kind='100644',self.blob(repo,value),'blob'
                entries.append((name,mode,kind,oid))
            data=b''.join(f'{mode} {kind} {oid}\t{name}\0'.encode() for name,mode,kind,oid in sorted(entries,key=lambda x:(x[0]+('/' if x[1]=='040000' else '')).encode()))
            return native(self.repos[repo],'mktree','-z','--missing',data=data).strip().decode()
        tree_oid=tree(nodes); self.sequence+=1
        args=['commit-tree',tree_oid]
        for p in parents:args+=['-p',p]
        oid=native(self.repos[repo],*args,data=(label or f'fixture {self.sequence}').encode()+b'\n').strip().decode()
        self.commits[repo][oid]={'parents':tuple(parents),'tree':tree_oid,'files':dict(files)}
        if update:native(self.repos[repo],'update-ref','refs/heads/main',oid)
        return oid
    def spec(self,roots,bindings=(),limits=None):
        from historycrate.model import Spec,RepoSpec,RootSpec,Binding
        from historycrate.limits import Limits
        return Spec(1,tuple(RepoSpec(k,p,p/'lfs/objects') for k,p in self.repos.items()),
                    tuple(RootSpec(k,r,tuple(cs)) for k,r,cs in roots),tuple(Binding(*b) for b in bindings),limits or Limits())

def modules(*entries):
    return ''.join(f'[submodule "{name}"]\n path = {path}\n url = {url}\n' for name,path,url in entries).encode()

def inventory(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
