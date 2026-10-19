"""Tiny original capability probes only; no user repository acquisition pipeline."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import time

from .native import Job, _config, _git_prefix, _trusted_path, refuse, sha256
from .paths import check_filesystem_capabilities, open_directory, open_regular_beneath


def _blob(a,repo,data):
    return a.run('hash_blob',{'repo':repo,'write':True},data).stdout.strip().decode()


def _commit(a,repo,files):
    tree_data=b''.join(f'100644 blob {oid}\t{name}\0'.encode() for name,oid in sorted(files.items()))
    tree=a.run('make_tree',{'repo':repo},tree_data).stdout.strip().decode()
    commit=a.run('commit_tree',{'repo':repo,'tree':tree,'parents':()},b'Original MIT qualification fixture\n').stdout.strip().decode()
    a.run('update_ref',{'repo':repo,'oid':commit})
    return commit


def _trace_lfs(a,cwd,path,expected,env=None,ordinary=False):
    # Built-in tracing is allowed. It is not ptrace or syscall/network tracing.
    trace=a.root/'artifacts'/('trace-'+str(len(a.records))+'.jsonl')
    trace_env=dict(env or a.environment);trace_env['GIT_TRACE2_EVENT']=str(trace)
    prefix=[str(a.tools.git),'--no-pager'] if ordinary else _git_prefix(a.tools.git,a.tools)
    args=prefix+['hash-object','--path='+path,'--',path]
    result=a._execute(args,cwd,env=trace_env)
    if result.stdout.strip().decode()!=expected:refuse('CLEAN_ROUNDTRIP_FAILED',4)
    data=trace.read_bytes()
    if len(data)>a.limits.captured_bytes:refuse('BUDGET_EXCEEDED',5,resource='trace')
    records=[json.loads(line) for line in data.splitlines()]
    versions=[r for r in records if r.get('event')=='version']
    internal=[r for r in versions if '/' in r.get('sid','')]
    if not internal or any(r.get('exe')!=a.tools.git_version for r in versions):
        refuse('LFS_INTERNAL_GIT_MISMATCH',3)
    expected_process=_config(a.tools)['filter.lfs.process']
    child_starts=[r.get('argv') for r in records if r.get('event')=='child_start']
    if [expected_process] not in child_starts:refuse('LFS_PROCESS_IDENTITY_UNOBSERVED',3)
    resolver_paths=(a.tools.git,a.tools.git_exec_path/'git')
    if not all(os.path.samefile(a.tools.git,p) for p in resolver_paths):refuse('GIT_RESOLVER_IDENTITY_CHANGED',4)
    return {'method':'Git Trace2 versions plus fixed resolver inode identity',
            'internal_git_version_events':len(internal),'internal_git_versions':sorted({r['exe'] for r in internal}),
            'resolver_paths':[str(p) for p in resolver_paths],
            'resolver_same_inode':True,'fixed_lfs_command_observed':expected_process,
            'trace_sha256':sha256(trace),'trace_bytes':len(data),'trace_text':data.decode('utf-8'),
            'kernel_exec_trace':False,'network_syscall_observation':'unavailable; not claimed'}


def _copy_original_fixture_objects(a,source,target,commit):
    """Gate-only fixture copier: canonical regular loose objects, with no source Git invocation."""
    src_git=source/'.git';target_git=target
    before={str(p.relative_to(src_git)):sha256(p) for p in src_git.rglob('*') if p.is_file()}
    source_fd=open_directory(src_git/'objects');count=0;bytecount=0
    try:
        for fanout in sorted((src_git/'objects').iterdir()):
            if fanout.name in ('info','pack'):
                if list(fanout.iterdir()):refuse('UNEXPECTED_QUALIFICATION_OBJECT_LAYOUT',6)
                continue
            if not re.fullmatch(r'[0-9a-f]{2}',fanout.name):refuse('INVALID_OBJECT_PATH',4)
            (target_git/'objects'/fanout.name).mkdir(mode=0o700,exist_ok=True)
            for path in sorted(fanout.iterdir()):
                if not re.fullmatch(r'[0-9a-f]{38}',path.name):refuse('INVALID_OBJECT_PATH',4)
                relative=fanout.name+'/'+path.name;fd=open_regular_beneath(source_fd,relative)
                try:
                    st=os.fstat(fd)
                    if st.st_size>a.limits.git_object_bytes:refuse('BUDGET_EXCEEDED',5)
                    data=b''
                    while len(data)<st.st_size:
                        chunk=os.read(fd,min(65536,st.st_size-len(data)))
                        if not chunk:refuse('SOURCE_CHANGED',4)
                        data+=chunk
                    if os.read(fd,1) or os.fstat(fd)!=st:refuse('SOURCE_CHANGED',4)
                finally:os.close(fd)
                destination=target_git/'objects'/relative
                with destination.open('xb') as out:out.write(data)
                destination.chmod(0o600);count+=1;bytecount+=len(data)
    finally:os.close(source_fd)
    after={str(p.relative_to(src_git)):sha256(p) for p in src_git.rglob('*') if p.is_file()}
    if before!=after:refuse('SOURCE_CHANGED',4)
    return {'objects_copied':count,'bytes_copied':bytecount,'source_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
            'source_files_before':before,'source_files_after':after,'same_source_content_hashes':True}


def qualify_capabilities(tools,limits):
    initial_as=resource.getrlimit(resource.RLIMIT_AS)
    with Job(limits,tools) as job:
        a=job.native;checks=[];expected_actual={}
        safeguards=qualify_safeguards(job.root,limits);checks.extend(safeguards)
        capabilities=check_filesystem_capabilities(job.root)
        checks+=['case_sensitive_filesystem','atomic_noreplace']
        a.run('init',{'name':'fixture','bare':False});repo=a._repo('fixture')
        payload=b'HistoryCrate original payload\n'
        pointer=f'version https://git-lfs.github.com/spec/v1\noid sha256:{hashlib.sha256(payload).hexdigest()}\nsize {len(payload)}\n'.encode()
        clean=a.run('lfs_clean',{'repo':'fixture','path':'data.bin'},payload).stdout
        if clean!=pointer:refuse('LFS_POINTER_MISMATCH',4)
        if a.run('lfs_smudge',{'repo':'fixture','path':'data.bin'},pointer).stdout!=pointer:refuse('LFS_SKIP_SMUDGE_FAILED',4)
        if a.run('lfs_clean',{'repo':'fixture','path':'empty.bin'},b'').stdout!=b'':refuse('LFS_EMPTY_FAILED',4)
        checks+=['lfs_exact_pointer','lfs_skip_smudge','lfs_empty']
        expected_actual['lfs_pointer']={'expected_hex':pointer.hex(),'actual_hex':clean.hex(),'payload_bytes':len(payload)}
        attr=b'*.txt text eol=crlf\n*.bin filter=lfs -text\n'
        text_blob=b'one\ntwo\n'
        files={'.gitattributes':_blob(a,'fixture',attr),'text.txt':_blob(a,'fixture',text_blob),'empty.bin':_blob(a,'fixture',b''),':wq':_blob(a,'fixture',b'colon\n')}
        names=['data.bin',"apostrophe'file.bin",'-leading.bin','space name.bin','semi;dollar$(x).bin']
        pointer_oid=_blob(a,'fixture',pointer)
        for name in names:files[name]=pointer_oid
        commit=_commit(a,'fixture',files)
        a.run('fsck',{'repo':'fixture'})
        attrs=a.run('check_attr',{'repo':'fixture','commit':commit,'paths':('text.txt','data.bin')}).stdout
        if b'text.txt\0eol\0crlf\0' not in attrs or b'data.bin\0filter\0lfs\0' not in attrs:refuse('HISTORICAL_ATTRIBUTES_FAILED',4)
        checks+=['historical_attributes']
        a.run('bundle_create',{'repo':'fixture','name':'fixture'})
        a.run('bundle_verify',{'repo':'fixture','name':'fixture'});checks+=['bundle']
        a.run('read_tree',{'repo':'fixture','commit':commit});a.run('checkout_index',{'repo':'fixture'})
        if (repo/'text.txt').read_bytes()!=b'one\r\ntwo\r\n':refuse('TEXT_CHECKOUT_BYTES_FAILED',4)
        if a.run('hash_path',{'repo':'fixture','path':'text.txt'}).stdout.strip().decode()!=files['text.txt']:refuse('TEXT_ROUNDTRIP_FAILED',4)
        expected_actual['text_checkout']={'expected_hex':b'one\r\ntwo\r\n'.hex(),'actual_hex':(repo/'text.txt').read_bytes().hex()}
        checks+=['text_roundtrip']
        for name in names:
            if (repo/name).read_bytes()!=pointer:refuse('LFS_SKIP_SMUDGE_FAILED',4)
            (repo/name).write_bytes(payload)
            if a.run('hash_path',{'repo':'fixture','path':name}).stdout.strip().decode()!=pointer_oid:refuse('FILTER_FILENAME_QUOTING_FAILED',4)
        if (repo/'empty.bin').read_bytes()!=b'':refuse('LFS_EMPTY_FAILED',4)
        checks+=['fixed_filter_punctuation']
        if a.run('status',{'repo':'fixture'}).stdout:refuse('FIXTURE_NOT_CLEAN',4)
        checks+=['native_clean_status']
        hygiene=qualify_hygiene(a,repo,pointer_oid)
        checks+=['helper_trap_positive_controls','helper_traps_suppressed','transport_denied']
        trace=_trace_lfs(a,repo,'data.bin',pointer_oid)
        checks+=['lfs_internal_git']
        global_config=job.root/'ordinary-global'
        escaped=str(tools.git_lfs).replace('\\','\\\\').replace('"','\\"')
        global_config.write_text('[filter "lfs"]\nprocess = "'+escaped+' filter-process"\nrequired = true\n')
        env=dict(a.environment);env['GIT_CONFIG_GLOBAL']=str(global_config);env['PATH']='/usr/bin:/bin'
        # Match ordinary post-publication selection: no -c filter overrides here.
        config_args=[str(tools.git),'--no-pager','config','--get','filter.lfs.process']
        if a._execute(config_args,repo,env=env).stdout.strip().decode()!=_config(tools)['filter.lfs.process']:refuse('PINNED_LOCAL_PROCESS_FILTER_FAILED',4)
        ordinary_args=[str(tools.git),'--no-pager','hash-object','--path=data.bin','--','data.bin']
        if a._execute(ordinary_args,repo,env=env).stdout.strip().decode()!=pointer_oid:refuse('NORMAL_GLOBAL_LFS_FAILED',4)
        ordinary_trace=_trace_lfs(a,repo,'data.bin',pointer_oid,env=env,ordinary=True)
        checks+=['normal_global_lfs_process_pinned']
        # Negative text conversion: a deliberately non-normalized stored CRLF blob must not round-trip.
        (repo/'text.txt').write_bytes(b'one\r\ntwo\r\n')
        raw_crlf=_blob(a,'fixture',b'one\r\ntwo\r\n')
        if a.run('hash_path',{'repo':'fixture','path':'text.txt'}).stdout.strip().decode()==raw_crlf:refuse('TEXT_NEGATIVE_FIXTURE_FAILED',6)
        checks+=['text_non_roundtrip_detected']
        # Source config is now poisoned. Never run native Git in this source after this point.
        src_config=repo/'.git/config'
        marker=job.root/'source-execution-marker'
        with src_config.open('a') as f:
            f.write(f'\n[filter "evil"]\nclean = "touch {marker}"\n[credential]\nhelper = "!touch {marker}"\n[core]\nfsmonitor = "touch {marker}"\n[remote "origin"]\nurl = "trap::no-network"\n')
        hooks=repo/'.git/hooks';hooks.mkdir(mode=0o700,exist_ok=True)
        (hooks/'post-checkout').write_text('#!/bin/sh\ntouch '+str(marker)+'\n');(hooks/'post-checkout').chmod(0o700)
        del a.repositories['fixture']
        inert=job.root/'source-config';inert.write_bytes(src_config.read_bytes());inert.chmod(0o600)
        parsed=a.run('parse_config',{'name':'source-config'}).stdout
        if b'filter.evil.clean\n' not in parsed or marker.exists():refuse('SOURCE_CONFIG_EXECUTED',6)
        checks+=['source_config_inert']
        a.run('init',{'name':'copied','bare':True});copied=a._repo('copied')
        copy=_copy_original_fixture_objects(a,repo,copied,commit)
        a.run('update_ref',{'repo':'copied','oid':commit});a.run('fsck',{'repo':'copied'})
        if marker.exists():refuse('SOURCE_HELPER_EXECUTED',6)
        checks+=['source_objects_copied','source_hashes_unchanged','source_traps_not_invoked']
        if resource.getrlimit(resource.RLIMIT_AS)!=initial_as:refuse('INHERITED_LIMIT_CHANGED',6)
        checks+=['inherited_address_space_unchanged']
        report={'report_version':1,'status':'passed','profile':'trusted-local-v1','publication':'not-published',
                'scope':'Gate 0 capability probes only; no inspect/pack/restore implementation or release qualification',
                'trust_acknowledged':True,'fixture_trust':'authored original tiny local fixtures','checks':checks,'rehearsed':[],
                'os_sandbox':False,'network_containment':False,'hard_job_quota':False,
                'inherited_address_space_limit':list(initial_as),'limits':limits.as_dict(),
                'resource_observation':'observed RSS and scratch are sampled abort thresholds; native peaks may be larger',
                'tools':{'git':str(tools.git),'git_version':tools.git_version,'git_lfs':str(tools.git_lfs),'lfs_version':tools.lfs_version,'git_exec_path':str(tools.git_exec_path),'sha256':dict(tools.hashes)},
                'expected_actual':expected_actual,'hygiene':hygiene,'safeguards':safeguards,'trace':trace,'ordinary_trace':ordinary_trace,'source_copy':copy,'commands':a.records,
                'limits_disclosed':['No OS sandbox or network namespace','No aggregate RSS/task/scratch hard cap','Procfs samples can miss peaks and short-lived descendants','No new RLIMIT_AS; inherited host limits unchanged','No user repositories read by doctor']}
        return report


def qualify_safeguards(root,limits):
    """Bounded original doctor self-checks; failures are the expected outcomes."""
    import sys
    from .errors import CrateError
    from .process import run_process
    script=root/'doctor-process-probe.py'
    script.write_text('''import os,signal,subprocess,sys,threading,time
from pathlib import Path
mode=sys.argv[1]
if mode=='allocate':
 data=bytearray(96*1024*1024)
 for i in range(0,len(data),4096):data[i]=1
 time.sleep(10)
elif mode=='family':
 def child():
  p=subprocess.Popen([sys.executable,__file__,'allocate'])
  p.wait()
 t=threading.Thread(target=child);t.start();t.join()
elif mode=='output':
 sys.stdout.buffer.write(b'x'*8192);sys.stdout.buffer.flush()
elif mode=='timeout':
 signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(10)
''')
    script.chmod(0o600)
    interpreter=Path(sys.executable).resolve();_trusted_path(interpreter)
    env={'PATH':'/usr/bin:/bin','HOME':str(root),'TMPDIR':str(root),'LANG':'C','LC_ALL':'C'}
    cases=(('observer_rss_abort','family',{'observed_rss_bytes':min(limits.observed_rss_bytes,64*1024*1024),'command_wall_seconds':min(limits.command_wall_seconds,4)},'OBSERVED_RSS_LIMIT'),
           ('capture_abort','output',{'captured_bytes':min(limits.captured_bytes,1024)},'CAPTURED_OUTPUT_LIMIT'),
           ('timeout_reaped','timeout',{'command_wall_seconds':min(limits.command_wall_seconds,1)},'COMMAND_TIMEOUT'))
    report={}
    for name,mode,overrides,code in cases:
        try:run_process((str(interpreter),str(script),mode),root,env,limits.lower(overrides),scratch=root)
        except CrateError as exc:
            observation=exc.context.get('observations',{})
            cleanup=observation.get('cleanup',{})
            if exc.code!=code or not cleanup.get('direct_child_reaped') or cleanup.get('uncertain'):
                raise
            if name=='observer_rss_abort':
                affected=exc.context.get('pid')
                if not any(p.get('pid')==affected and p.get('role')=='descendant' for p in observation.get('processes',[])):
                    refuse('OBSERVER_SELF_CHECK_DID_NOT_MEASURE_DESCENDANT',6)
            report[name]={'expected_failure_observed':True,'code':exc.code,'observations':observation}
        else:refuse('OBSERVER_SELF_CHECK_FAILED',6,check=name)
    return report


def qualify_hygiene(a,repo,pointer_oid):
    """Harmless tool-authored helper traps. Positive controls are intentional."""
    import sys
    import shlex
    from .process import run_process
    traps=a.root/'helper-traps';traps.mkdir(mode=0o700)
    interpreter=Path(sys.executable).resolve();_trusted_path(interpreter)
    names=('pre-commit','filter','fsmonitor','pager','credential','git-remote-trap')
    markers=[];positive=[]
    for name in names:
        marker=traps/(name+'.marker');markers.append(marker)
        helper=traps/name
        helper.write_text('#!'+str(interpreter)+'\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("called")\n')
        helper.chmod(0o700)
        result=run_process((str(helper),),traps,dict(a.environment),a.limits,scratch=a.root)
        if result.returncode or marker.read_text()!='called':refuse('TRAP_POSITIVE_CONTROL_FAILED',6)
        positive.append(name);marker.unlink()
    global_config=a.root/'poisoned-global'
    global_config.write_text('[core]\nhooksPath = '+str(traps)+'\nfsmonitor = '+str(traps/'fsmonitor')+'\npager = '+str(traps/'pager')+'\n[credential]\nhelper = !'+str(traps/'credential')+'\n[filter "lfs"]\nprocess = '+str(traps/'filter')+'\n')
    env=dict(a.environment);env['GIT_CONFIG_GLOBAL']=str(global_config)
    # This controlled qualification PATH adds only our harmless remote-helper trap.
    env['PATH']=str(traps)+':'+env['PATH']
    prefix=_git_prefix(a.tools.git,a.tools)
    if a._execute(prefix+['hash-object','--path=data.bin','--','data.bin'],repo,env=env).stdout.strip().decode()!=pointer_oid:refuse('FILTER_HYGIENE_FAILED',6)
    a._execute(prefix+['status','--porcelain=v1','-z'],repo,env=env)
    a._execute(prefix+['hook','run','pre-commit'],repo,env=env,expected_codes=(1,))
    credential=a._execute(prefix+['credential','fill'],repo,b'protocol=https\nhost=example.invalid\n\n',env=env,expected_codes=(128,))
    if credential.returncode!=128:refuse('CREDENTIAL_PROMPT_SUPPRESSION_FAILED',6)
    transport=a._execute(prefix+['ls-remote','trap::fixture'],repo,env=env,expected_codes=(128,))
    if transport.returncode!=128 or b"transport 'trap' not allowed" not in transport.stderr:refuse('TRANSPORT_REFUSAL_FAILED',6)
    if any(marker.exists() for marker in markers):refuse('HELPER_TRAP_EXECUTED',6)
    return {'positive_controls':positive,'negative_marker_writes':0,'transport_returncode':transport.returncode,
            'transport_stderr_sha256':hashlib.sha256(transport.stderr).hexdigest(),
            'network_scope':'explicit transport refusal; no OS network containment or syscall observation claimed'}
