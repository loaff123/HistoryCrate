"""Fixed native operations for trusted-local-v1. This is not an OS sandbox."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import stat
import tempfile
import time
from types import MappingProxyType
from typing import BinaryIO

from .errors import CrateError
from .limits import Limits, Budget
from .process import run_process, ProcessResult

ID = re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
OID = re.compile(r'[0-9a-f]{40}\Z')


def refuse(code, status=3, **context):
    raise CrateError(code, status, context)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _identity(path: Path):
    st = path.stat(follow_symlinks=False)
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _trusted_path(path: Path, basename: str | None = None, directory=False):
    if not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts:
        refuse('UNTRUSTED_EXECUTABLE')
    if basename and path.name != basename:
        refuse('WRONG_EXECUTABLE_NAME')
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        try:
            st = current.lstat()
        except OSError:
            refuse('TOOL_UNAVAILABLE')
        if stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022:
            # Private task tools can have /tmp as ancestor, but never as their parent.
            if not (current == Path('/tmp') and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX):
                refuse('UNTRUSTED_EXECUTABLE_PATH')
    st = path.stat(follow_symlinks=False)
    if directory:
        if not stat.S_ISDIR(st.st_mode):refuse('INVALID_EXEC_PATH')
    elif not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
        refuse('INVALID_EXECUTABLE')


@dataclass(frozen=True)
class Toolchain:
    git: Path
    git_lfs: Path
    git_exec_path: Path
    git_version: str
    lfs_version: str
    identities: object
    hashes: object


# These are tool-owned values. No source config value is interpolated.
def _config(tools: Toolchain | None = None):
    values = {
        'core.hooksPath':'/dev/null','core.attributesFile':'/dev/null',
        'core.autocrlf':'false','core.filemode':'true','core.ignorecase':'false',
        'core.fsmonitor':'false','core.untrackedCache':'false','core.pager':'cat',
        'gc.auto':'0','maintenance.auto':'false','protocol.allow':'never',
        'protocol.file.allow':'never','credential.helper':'','credential.interactive':'false',
        'submodule.recurse':'false','fetch.recurseSubmodules':'false',
        'diff.external':'','diff.trustExitCode':'false','pack.threads':'1','index.threads':'1',
        'user.name':'HistoryCrate Fixture','user.email':'fixture@example.invalid',
    }
    if tools:
        assignments=f'PATH={shlex.quote(str(tools.git.parent))} GIT_EXEC_PATH={shlex.quote(str(tools.git_exec_path))}'
        command=f'{assignments} {shlex.quote(str(tools.git_lfs))}'
        values.update({'filter.lfs.clean':command+' clean -- %f',
                       'filter.lfs.smudge':command+' smudge --skip -- %f',
                       'filter.lfs.process':command+' filter-process --skip','filter.lfs.required':'true',
                       'lfs.concurrenttransfers':'1'})
    return values


def _tool_path(git: Path):
    return ':'.join(dict.fromkeys((str(git.parent),'/usr/bin','/bin')))


def _environment(root: Path, git: Path, exec_path: Path | None = None):
    for name in ('home','xdg','tmp','template','repos','artifacts'):
        (root/name).mkdir(mode=0o700,exist_ok=True)
    (root/'empty-global').touch(mode=0o600,exist_ok=True)
    env = {
        'PATH':_tool_path(git),'HOME':str(root/'home'),'XDG_CONFIG_HOME':str(root/'xdg'),
        'TMPDIR':str(root/'tmp'),'LANG':'C','LC_ALL':'C','TZ':'UTC',
        'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':str(root/'empty-global'),
        'GIT_CONFIG_SYSTEM':'/dev/null','GIT_ATTR_NOSYSTEM':'1',
        'GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1',
        'GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','GIT_ALLOW_PROTOCOL':'',
        'GIT_PAGER':'cat','GIT_EDITOR':'false','GIT_SEQUENCE_EDITOR':'false',
        'GIT_TEMPLATE_DIR':str(root/'template'),'GOMAXPROCS':'2',
        'GIT_AUTHOR_DATE':'2001-01-01T00:00:00+0000','GIT_COMMITTER_DATE':'2001-01-01T00:00:00+0000',
    }
    if exec_path:env['GIT_EXEC_PATH']=str(exec_path)
    return env


def _git_prefix(git: Path, tools=None):
    args=[str(git),'--no-pager']
    for key,value in _config(tools).items():args.extend(('-c',key+'='+value))
    return args


def qualify_toolchain(git: Path, git_lfs: Path, limits: Limits, *, tool_guard=None) -> Toolchain:
    """Identity/version prerequisite check; doctor performs capability qualification."""
    if tool_guard is not None and not callable(tool_guard):refuse('INVALID_TOOL_GUARD',2)
    _trusted_path(git,'git');_trusted_path(git_lfs,'git-lfs')
    if tool_guard is not None:tool_guard((git,git_lfs))
    before={str(p):_identity(p) for p in (git,git_lfs)}
    with tempfile.TemporaryDirectory(prefix='historycrate-bootstrap-') as d:
        root=Path(d);env=_environment(root,git)
        def probe(args):
            result=run_process(tuple(args),root,env,limits,scratch=root)
            if result.returncode:refuse('TOOL_PROBE_FAILED')
            return result.stdout.strip().decode('ascii','strict')
        gv=probe(_git_prefix(git)+['--version'])
        ep=Path(probe(_git_prefix(git)+['--exec-path']))
        _trusted_path(ep,directory=True)
        # The exec path must belong to the same explicitly selected installation.
        if git.parent.parent not in ep.parents:refuse('GIT_EXEC_PATH_MISMATCH')
        _trusted_path(ep/'git','git')
        if not os.path.samefile(git,ep/'git'):refuse('GIT_EXEC_PATH_BINARY_MISMATCH')
        # A caller may exclude input/output locations without trusting native
        # version operations to avoid internally resolving Git from this tree.
        if tool_guard is not None:tool_guard((ep,ep/'git'))
        env['GIT_EXEC_PATH']=str(ep)
        lv=probe([str(git_lfs),'version'])
        if gv!='git version 2.52.0':refuse('UNQUALIFIED_GIT_VERSION')
        if not re.fullmatch(r'git-lfs/3\.8\.0 \(GitHub; linux amd64; go [^;]+; git [0-9a-f]+\)',lv):
            refuse('UNQUALIFIED_LFS_VERSION')
    for p in (git,git_lfs):
        if before[str(p)]!=_identity(p):refuse('TOOL_CHANGED',4)
    before[str(ep/'git')]=_identity(ep/'git')
    return Toolchain(git,git_lfs,ep,'2.52.0','3.8.0',MappingProxyType(before),
                     MappingProxyType({str(p):sha256(p) for p in (git,git_lfs,ep/'git')}))


def _name(value):
    if not isinstance(value,str) or not ID.fullmatch(value):refuse('INVALID_NATIVE_PARAMETER',2)
    return value


def _oid(value):
    if not isinstance(value,str) or not OID.fullmatch(value):refuse('INVALID_NATIVE_PARAMETER',2)
    return value


def _path(value, limits=None):
    from .paths import validate_relative_path
    parts=validate_relative_path(value)
    limits=limits or Limits()
    if len(value.encode())>limits.path_bytes or len(parts)>limits.path_depth or any(len(p.encode())>limits.component_bytes for p in parts):
        refuse('BUDGET_EXCEEDED',5,resource='path')
    return value


class _ObjectFrame:
    """Validate one cat-file frame while forwarding only payload bytes."""
    framing_overhead = 202
    def __init__(self, sink, oid, limit, *, verify=False):
        self.sink=sink;self.oid=oid;self.limit=limit;self.header=bytearray();self.remaining=None;self.ended=False
        self.verify=verify;self.kind=None;self.size=None;self.digest=None
    def write(self,data):
        data=bytes(data)
        total=len(data)
        if self.remaining is None:
            split=data.find(b'\n')
            if split<0:
                self.header.extend(data)
                if len(self.header)>200:refuse('INVALID_OBJECT_FRAME',4)
                return total
            self.header.extend(data[:split]);data=data[split+1:]
            if len(self.header)>200:refuse('INVALID_OBJECT_FRAME',4)
            if self.header == (self.oid+' missing').encode():refuse('MISSING_OBJECT',4,oid=self.oid)
            match=re.fullmatch(rb'([0-9a-f]{40}) (blob|tree|commit|tag) (0|[1-9][0-9]*)',self.header)
            if not match or match[1].decode()!=self.oid:refuse('INVALID_OBJECT_FRAME',4)
            size=int(match[3])
            if size>self.limit:refuse('BUDGET_EXCEEDED',5,resource='git_object_bytes')
            self.remaining=size;self.kind=match[2].decode();self.size=size
            if self.verify:self.digest=hashlib.sha1(match[2]+b' '+match[3]+b'\0')
        if self.remaining:
            n=min(self.remaining,len(data));part=data[:n]
            if self.sink.write(part)!=n:refuse('STREAM_WRITE_FAILED',6)
            if self.digest is not None:self.digest.update(part)
            self.remaining-=n;data=data[n:]
        if data:
            if self.remaining or self.ended or data!=b'\n':refuse('INVALID_OBJECT_FRAME',4)
            self.ended=True
        return total
    def finish(self):
        if self.remaining!=0 or not self.ended:refuse('TRUNCATED_OBJECT_FRAME',4)
        if self.verify and self.digest.hexdigest()!=self.oid:refuse('OBJECT_HASH_MISMATCH',4,oid=self.oid)


class NativeAdapter:
    def __init__(self,root:Path,tools:Toolchain,limits:Limits,*,observation_root=None,started=None):
        self.root=root;self.tools=tools;self.limits=limits;self.observation_root=observation_root or root
        self.environment=MappingProxyType(_environment(root,tools.git,tools.git_exec_path))
        self.repositories={};self.records=[];self.started=time.monotonic() if started is None else started;self.busy=False
    def _validate_tools(self):
        for p in (self.tools.git,self.tools.git_lfs,self.tools.git_exec_path/'git'):
            if self.tools.identities.get(str(p))!=_identity(p):refuse('TOOL_CHANGED',4)
        if not os.path.samefile(self.tools.git,self.tools.git_exec_path/'git'):refuse('GIT_RESOLVER_IDENTITY_CHANGED',4)
    def _execute(self,args,cwd,stdin=b'',sink=None,env=None,expected_codes=(),converted_output_limit=None,lfs_payload_input=False):
        if self.busy or self.limits.native_commands<1:refuse('NATIVE_CONCURRENCY_REFUSED',5)
        if time.monotonic()-self.started>self.limits.job_wall_seconds:refuse('BUDGET_EXCEEDED',5,resource='job_wall_seconds')
        self._validate_tools();self.busy=True
        try:
            result=run_process(tuple(args),cwd,dict(env or self.environment),self.limits,stdin,sink=sink,scratch=self.observation_root,absolute_deadline=self.started+self.limits.job_wall_seconds,converted_output_limit=converted_output_limit,lfs_payload_input=lfs_payload_input)
            self._validate_tools()
            self.records.append({'argv':list(args),'returncode':result.returncode,'stderr_sha256':hashlib.sha256(result.stderr).hexdigest(),'observations':result.observations})
            if result.returncode and result.returncode not in expected_codes:refuse('NATIVE_COMMAND_FAILED',4,returncode=result.returncode,stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
            if time.monotonic()-self.started>self.limits.job_wall_seconds:refuse('BUDGET_EXCEEDED',5,resource='job_wall_seconds')
            return result
        finally:self.busy=False
    def _repo(self,name):
        name=_name(name)
        if name not in self.repositories:refuse('UNREGISTERED_STAGING_REPOSITORY',3)
        path,bare,identity=self.repositories[name]
        st=path.stat(follow_symlinks=False)
        if (st.st_dev,st.st_ino)!=identity:refuse('STAGING_CHANGED',4)
        return path
    def _prepare(self,operation,parameters,stdin):
        if not isinstance(parameters,dict):refuse('INVALID_NATIVE_PARAMETER',2)
        keys={
            'git_version':set(),'lfs_version':set(),'init':{'name','bare'},
            'init_child':{'name','parent','path'},'detach_head':{'repo','oid'},
            'head':{'repo'},'head_symbolic':{'repo'},'index':{'repo'},
            'diff_worktree':{'repo'},'diff_index':{'repo'},'submodule_status':{'repo'},
            'register_submodule':{'repo','name','path','child'},
            'config_list':{'repo'},'parse_config':{'name'},'hash_blob':{'repo','write'},
            'make_tree':{'repo'},'commit_tree':{'repo','tree','parents'},'update_ref':{'repo','oid'},
            'fsck':{'repo'},'fsck_acquired':{'repo'},'fsck_roots':{'repo','oids'},'list_objects':{'repo'},'rebuild_pack':{'repo','pack'},'bundle_create':{'repo','name'},'bundle_verify':{'repo','name'},
            'check_attr':{'repo','commit','paths'},'read_tree':{'repo','commit'},
            'checkout_index':{'repo'},'hash_path':{'repo','path'},'status':{'repo'},
            'lfs_clean':{'repo','path'},'lfs_smudge':{'repo','path'},'lfs_fsck':{'repo','commit'},'cat_object':{'repo','oid'},
            'conversion_checkout':{'repo','commit','path','oid','name'},
            'conversion_hash':{'repo','commit','path','name'},
            'install_seeds':{'repo','oids'},'bundle_selected':{'repo','name','oids'},'unbundle':{'repo','name'},
        }
        if operation not in keys:refuse('UNSUPPORTED_NATIVE_OPERATION',3)
        if set(parameters)!=keys[operation]:refuse('INVALID_NATIVE_PARAMETER',2)
        p=parameters;args=_git_prefix(self.tools.git,self.tools);cwd=self.root
        if 'repo' in p:cwd=self._repo(p['repo'])
        if operation=='git_version':args+=['--version']
        elif operation=='lfs_version':args=[str(self.tools.git_lfs),'version']
        elif operation=='init':
            name=_name(p['name'])
            if type(p['bare']) is not bool or name in self.repositories:refuse('INVALID_NATIVE_PARAMETER',2)
            dest=self.root/'repos'/name
            if dest.exists() or dest.is_symlink():refuse('STAGING_EXISTS',6)
            args+=['init','--quiet','--object-format=sha1','--initial-branch=historycrate','--template='+str(self.root/'template')]
            if p['bare']:args+=['--bare']
            args+=[str(dest)]
        elif operation=='init_child':
            name=_name(p['name']);parent=self._repo(p['parent']);path=_path(p['path'],self.limits)
            if name in self.repositories or self.repositories[p['parent']][1]:refuse('INVALID_NATIVE_PARAMETER',2)
            dest=parent/path
            from .paths import open_directory
            fd=open_directory(dest)
            try:
                if os.listdir(fd):refuse('STAGING_EXISTS',6)
            finally:os.close(fd)
            args+=['init','--quiet','--object-format=sha1','--initial-branch=historycrate','--template='+str(self.root/'template'),str(dest)]
        elif operation=='detach_head':args+=['update-ref','--no-deref','HEAD',_oid(p['oid'])]
        elif operation=='head':args+=['rev-parse','--verify','HEAD']
        elif operation=='head_symbolic':args+=['symbolic-ref','--quiet','HEAD']
        elif operation=='index':args+=['ls-files','--stage','-v','-z']
        elif operation in ('diff_worktree','diff_index'):
            args+=['diff','--exit-code','--no-ext-diff','--no-textconv','--ignore-submodules=none']
            if operation=='diff_index':args+=['--cached']
            args+=['--']
        elif operation=='submodule_status':args+=['-c','core.quotePath=false','submodule','status','--recursive']
        elif operation=='register_submodule':
            if not isinstance(p['name'],str) or not re.fullmatch(r'[A-Za-z0-9._/-]{1,200}',p['name']):refuse('INVALID_NATIVE_PARAMETER',2)
            _path(p['path'],self.limits);_name(p['child'])
            args+=['config','--local','--add','submodule.'+p['name']+'.url','historycrate-offline:'+p['child']]
        elif operation=='config_list':args+=['config','--null','--list','--local']
        elif operation=='parse_config':
            name=_name(p['name']);path=self.root/name
            from .paths import open_regular_beneath
            fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try:
                f=open_regular_beneath(fd,name)
                try:
                    if os.fstat(f).st_size>self.limits.config_bytes:refuse('BUDGET_EXCEEDED',5,resource='config_bytes')
                finally:os.close(f)
            finally:os.close(fd)
            args+=['config','--no-includes','--file',str(path),'--null','--list']
        elif operation=='hash_blob':
            if type(p['write']) is not bool:refuse('INVALID_NATIVE_PARAMETER',2)
            args+=['hash-object']+(['-w'] if p['write'] else [])+['--stdin']
        elif operation=='make_tree':args+=['mktree','-z']
        elif operation=='commit_tree':
            if not isinstance(p['parents'],tuple) or len(p['parents'])>64:refuse('INVALID_NATIVE_PARAMETER',2)
            args+=['commit-tree',_oid(p['tree'])]
            for parent in p['parents']:args+=['-p',_oid(parent)]
        elif operation=='update_ref':args+=['update-ref','refs/heads/historycrate',_oid(p['oid'])]
        elif operation in ('fsck','fsck_acquired','fsck_roots'):
            args+=['fsck','--full','--strict','--no-reflogs','--no-dangling']
            if operation=='fsck_roots':
                if not isinstance(p['oids'],tuple) or not 1<=len(p['oids'])<=512:refuse('INVALID_NATIVE_PARAMETER',2)
                args += [_oid(value) for value in p['oids']]
        elif operation=='list_objects':args+=['cat-file','--batch-all-objects','--batch-check']
        elif operation=='rebuild_pack':
            # Do not use --strict here: graph links may live in another pack.
            # index-pack verifies the pack checksum, object bytes and delta bases;
            # full-store strict fsck runs only after every index has been rebuilt.
            pack=cwd/'objects'/'pack'/('pack-'+_oid(p['pack'])+'.pack')
            args+=['index-pack','--index-version=2',str(pack)]
        elif operation=='install_seeds':
            oids=p['oids']
            if not isinstance(oids,tuple) or not 1<=len(oids)<=self.limits.bundle_seed_refs or len(set(oids))!=len(oids):refuse('INVALID_NATIVE_PARAMETER',2)
            if stdin:refuse('INVALID_NATIVE_PARAMETER',2)
            stdin=b''.join(f'create refs/historycrate/commits/{_oid(oid)} {oid}\n'.encode() for oid in oids)
            args+=['update-ref','--stdin']
        elif operation in ('bundle_selected','unbundle'):
            bundle=self.root/'artifacts'/(_name(p['name'])+'.bundle')
            args+=['bundle','create','--version=2',str(bundle)] if operation=='bundle_selected' else ['bundle','unbundle',str(bundle)]
            if operation=='bundle_selected':
                if bundle.exists() or bundle.is_symlink():refuse('STAGING_EXISTS',6)
                if not isinstance(p['oids'],tuple) or not 1<=len(p['oids'])<=self.limits.bundle_seed_refs:refuse('INVALID_NATIVE_PARAMETER',2)
                args+=[f'refs/historycrate/commits/{_oid(oid)}' for oid in p['oids']]
        elif operation.startswith('bundle_'):
            bundle=self.root/'artifacts'/(_name(p['name'])+'.bundle')
            args+=['bundle','create' if operation=='bundle_create' else 'verify',str(bundle)]
            if operation=='bundle_create':
                if bundle.exists() or bundle.is_symlink():refuse('STAGING_EXISTS',6)
                args+=['refs/heads/historycrate']
        elif operation=='check_attr':
            if not isinstance(p['paths'],tuple) or len(p['paths'])>1000 or stdin:refuse('INVALID_NATIVE_PARAMETER',2)
            stdin=b''.join(_path(x,self.limits).encode()+b'\0' for x in p['paths'])
            args+=['check-attr','--source='+_oid(p['commit']),'-z','--stdin','filter','text','eol','ident','working-tree-encoding']
        elif operation=='read_tree':args+=['read-tree','--reset',_oid(p['commit'])]
        elif operation=='checkout_index':args+=['checkout-index','--all','--force']
        elif operation=='hash_path':
            path=_path(p['path'],self.limits);args+=['hash-object','--path='+path,'--',path]
        elif operation=='status':args+=['status','--porcelain=v1','-z','--untracked-files=all','--ignore-submodules=none']
        elif operation in ('conversion_checkout','conversion_hash'):
            if stdin:refuse('INVALID_NATIVE_PARAMETER',2)
            path=_path(p['path'],self.limits);commit=_oid(p['commit']);name=_name(p['name'])
            worktree=self.root/'conversion-worktree'
            worktree.mkdir(mode=0o700,exist_ok=True)
            args+=['--work-tree='+str(worktree),'--attr-source='+commit]
            if operation=='conversion_checkout':
                args+=['cat-file','--filters','--path='+path,_oid(p['oid'])]
            else:
                artifact=self.root/'artifacts'/name
                from .paths import open_directory,open_regular_beneath
                fd=open_directory(artifact.parent)
                try:
                    source=open_regular_beneath(fd,name)
                    try:
                        if os.fstat(source).st_size>min(2*self.limits.git_object_bytes,self.limits.scratch_bytes,self.limits.command_file_bytes):refuse('BUDGET_EXCEEDED',5,resource='converted_file_bytes')
                    finally:os.close(source)
                finally:os.close(fd)
                args+=['hash-object','--path='+path,'--',str(artifact)]
        elif operation=='lfs_fsck':
            args=[str(self.tools.git_lfs),'fsck','--objects','--pointers',_oid(p['commit'])]
        elif operation in ('lfs_clean','lfs_smudge'):
            args=[str(self.tools.git_lfs),'clean' if operation=='lfs_clean' else 'smudge']
            if operation=='lfs_smudge':args+=['--skip']
            args+=['--',_path(p['path'],self.limits)]
        elif operation=='cat_object':
            if stdin:refuse('INVALID_NATIVE_PARAMETER',2)
            args+=['cat-file','--batch'];stdin=(_oid(p['oid'])+'\n').encode()
        return args,cwd,stdin
    def run(self,operation,parameters,stdin=b''):
        if operation=='cat_object':refuse('STREAM_REQUIRED',2)
        args,cwd,stdin=self._prepare(operation,parameters,stdin)
        if operation=='conversion_checkout':
            artifact=self.root/'artifacts'/parameters['name'];created=False
            try:
                with artifact.open('xb') as sink:
                    created=True
                    result=self._execute(args,cwd,stdin,sink=sink,converted_output_limit=min(2*self.limits.git_object_bytes,self.limits.scratch_bytes,self.limits.command_file_bytes))
                artifact.chmod(0o600)
            except BaseException:
                if created and artifact.is_file():artifact.unlink()
                raise
        else:result=self._execute(args,cwd,stdin,expected_codes=tuple(range(1,256)) if operation=='fsck_roots' else (1,) if operation=='head_symbolic' else (),lfs_payload_input=operation=='lfs_clean')
        if operation in ('init','init_child'):
            bare=parameters['bare'] if operation=='init' else False
            dest=self.root/'repos'/parameters['name'] if operation=='init' else self._repo(parameters['parent'])/parameters['path']
            config=dest/'config' if bare else dest/'.git/config'
            # Git generated only core layout fields. Append the fixed persistent profile.
            content=config.read_text()
            for key,value in _config(self.tools).items():
                parts=key.split('.')
                section=parts[0];subsection='.'.join(parts[1:-1]);leaf=parts[-1]
                heading=f'[{section} "{subsection}"]' if subsection else f'[{section}]'
                escaped=value.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n')
                content+=f'\n{heading}\n\t{leaf} = "{escaped}"\n'
            config.write_text(content);config.chmod(0o600)
            st=dest.stat();self.repositories[parameters['name']]=(dest,bare,(st.st_dev,st.st_ino))
        if operation=='register_submodule':
            config=cwd/'.git/config'
            values={'path':parameters['path'],'active':'true','update':'none','ignore':'none'}
            with config.open('a') as out:
                out.write('\n[submodule \"'+parameters['name']+'\"]\n')
                for key,value in values.items():
                    escaped=value.replace('\\','\\\\').replace('\"','\\\"')
                    out.write('\t'+key+' = \"'+escaped+'\"\n')
        if operation=='install_seeds':
            gitdir=cwd if self.repositories[parameters['repo']][1] else cwd/'.git'
            (gitdir/'HEAD').write_text(parameters['oids'][0]+'\n')
        if operation=='fsck' and (result.stdout or result.stderr):
            # Empty fixture repositories may print notices; qualified nonempty stores may not.
            refuse('NATIVE_INTEGRITY_DIAGNOSTIC',4)
        if operation=='fsck_roots' and result.returncode:
            # Convert only exact, bounded native missing-object lines to safe typed
            # diagnostics. Unknown warnings/errors remain fatal and hashed.
            allowed_stderr={b'notice: HEAD points to an unborn branch (historycrate)',b'notice: No default references'}
            missing=[];known=True
            for line in result.stdout.splitlines():
                match=re.fullmatch(rb'missing (blob|tree|commit) ([0-9a-f]{40})',line)
                if match:missing.append((match[1].decode(),match[2].decode()))
                elif not re.fullmatch(rb'(?:broken link from|              to) +(?:blob|tree|commit|tag) [0-9a-f]{40}',line):known=False
            if known and missing and all(line in allowed_stderr for line in result.stderr.splitlines()):
                kind,oid=sorted(missing)[0]
                refuse({'blob':'MISSING_BLOB','tree':'MISSING_TREE','commit':'MISSING_PARENT'}[kind],4,repository=parameters['repo'],oid=oid)
            refuse('NATIVE_INTEGRITY_DIAGNOSTIC',4,returncode=result.returncode,stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
        if operation in ('fsck_acquired','fsck_roots'):
            allowed={b'notice: HEAD points to an unborn branch (historycrate)',b'notice: No default references'}
            lines=result.stderr.splitlines()
            if result.stdout or len(lines)!=len(set(lines)) or any(line not in allowed for line in lines):
                refuse('NATIVE_INTEGRITY_DIAGNOSTIC',4)
        if operation=='list_objects' and result.stderr:refuse('NATIVE_INTEGRITY_DIAGNOSTIC',4)
        if operation=='rebuild_pack':
            if result.stderr or result.stdout != (parameters['pack']+'\n').encode():
                refuse('NATIVE_INTEGRITY_DIAGNOSTIC',4)
        return result
    def stream_object(self,repo,oid,sink):
        args,cwd,stdin=self._prepare('cat_object',{'repo':repo,'oid':oid},b'')
        frame=_ObjectFrame(sink,oid,self.limits.git_object_bytes,verify=True)
        result=self._execute(args,cwd,stdin,sink=frame);frame.finish()
        if result.stderr:refuse('NATIVE_INTEGRITY_DIAGNOSTIC',4)
        return frame.kind,frame.size
    def stream(self,operation,parameters,source:BinaryIO,sink:BinaryIO):
        if operation!='cat_object' or source.read(1):refuse('UNSUPPORTED_STREAM_OPERATION',2)
        args,cwd,stdin=self._prepare(operation,parameters,b'')
        frame=_ObjectFrame(sink,parameters['oid'],self.limits.git_object_bytes)
        result=self._execute(args,cwd,stdin,sink=frame);frame.finish();return result


class Job:
    def __init__(self,limits,tools,output_parent=None,source_paths=()):
        self.limits=limits;self.tools=tools;self.output_parent=output_parent;self.source_paths=source_paths
        self.root=None;self.native=None;self.budget=Budget(limits);self._temp=None
    def __enter__(self):
        from .paths import open_directory, private_directory, protected_worktree_root, _ancestors
        effective_parent=Path(self.output_parent) if self.output_parent is not None else Path(tempfile.gettempdir())
        if self.output_parent is None and effective_parent==Path('/tmp'):
            parent_fd=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        else:parent_fd=open_directory(effective_parent)
        try:parent_ancestors=_ancestors(parent_fd)
        finally:os.close(parent_fd)
        for p in self.source_paths:
            protected=protected_worktree_root(Path(p))
            for source in (Path(p),protected):
                if source is None:continue
                guard_fd=open_directory(source)
                try:
                    guard=os.fstat(guard_fd)
                    if (guard.st_dev,guard.st_ino) in parent_ancestors:refuse('SCRATCH_INSIDE_SOURCE')
                finally:os.close(guard_fd)
            fd=open_directory(Path(p))
            try:
                info=os.fstat(fd);source_identity=(info.st_dev,info.st_ino)
                for tool in (self.tools.git,self.tools.git_lfs,self.tools.git_exec_path):
                    for parent in (tool,*tool.parents):
                        st=parent.stat(follow_symlinks=False)
                        if source_identity==(st.st_dev,st.st_ino):refuse('SOURCE_PATH_CANNOT_BE_TOOL')
            finally:os.close(fd)
        self._temp=private_directory(self.output_parent,prefix='historycrate-job-')
        self._owned=self._temp.__enter__()
        self.root=self._owned.path
        for tool in (self.tools.git,self.tools.git_lfs):
            if self.root==tool or self.root in tool.parents:refuse('SOURCE_PATH_CANNOT_BE_TOOL')
        self.native=NativeAdapter(self.root,self.tools,self.limits)
        return self
    def __exit__(self,typ,value,tb):
        # A lifecycle failure with unknown expected-child status keeps owned scratch for inspection.
        context=getattr(value,'context',{}) if isinstance(value,CrateError) else {}
        if context.get('cleanup_uncertain') or context.get('observations',{}).get('cleanup',{}).get('uncertain'):
            self._owned.preserve()
        if self._temp:self._temp.__exit__(typ,value,tb)
        return False


def doctor(git:Path,git_lfs:Path,limits:Limits|None=None,*,tool_guard=None):
    from .qualification import qualify_capabilities
    return qualify_capabilities(qualify_toolchain(git,git_lfs,limits or Limits(),tool_guard=tool_guard),limits or Limits())
