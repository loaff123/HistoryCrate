"""Independent exhaustive/native oracle; no production closure/manifest imports."""
from tests.fixtures.histories import native

def ancestry(repo,seeds):
    return set(native(repo,'rev-list',*seeds).decode().splitlines())

def objects(repo,seeds):
    return set(native(repo,'rev-list','--objects','--no-object-names',*seeds).decode().splitlines())

def gitlinks(repo,commits):
    result=set()
    for commit in commits:
        for item in native(repo,'ls-tree','-rz',commit).split(b'\0'):
            if not item:continue
            info,path=item.split(b'\t',1);mode,kind,oid=info.split()
            if mode==b'160000':result.add((commit,path.decode(),oid.decode()))
    return result
