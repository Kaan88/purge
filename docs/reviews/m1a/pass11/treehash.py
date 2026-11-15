"""The engine tree hash of the handoffs, computed the way the Linux shell line does it:

    find crates bins -type f | sort | xargs -d "\\n" sha256sum | sha256sum

Git Bash on Windows gives another result for the same files (its sha256sum prints " *" between hash
and path, its sort orders differently from glibc's, and a Windows checkout may hold CRLF line
endings). This script reproduces the Linux result: the content is what git stores for each file
(the working tree as `git add` would take it, or a commit), paths with "/", ordered as glibc orders
them in a UTF-8 locale (letters and digits first, case ignored; the full path breaks ties), lines
of "<hash>  <path>". Files git ignores are left out.

usage: python -I treehash.py <repo> [<commit>]      (no commit: the working tree)
"""
import hashlib
import os
import subprocess
import sys
import tempfile

repo = sys.argv[1]
commit = sys.argv[2] if len(sys.argv) > 2 else None


def git(*args, env=None, data=None):
    return subprocess.run(['git', '-C', repo, *args], input=data, env=env, check=True,
                          capture_output=True).stdout


if commit:
    listing = git('ls-tree', '-r', '-z', commit, 'crates', 'bins')
else:
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(tmp, 'index'))
        git('read-tree', 'HEAD', env=env)
        git('add', '-A', '--', 'crates', 'bins', env=env)
        listing = git('ls-files', '-s', '-z', '--', 'crates', 'bins', env=env)
blobs = {}
for entry in listing.split(b'\0'):
    if entry:
        meta, path = entry.split(b'\t', 1)
        fields = meta.split()
        blobs[path.decode()] = (fields[2] if commit else fields[1]).decode()
paths = sorted(blobs, key=lambda p: (''.join(c for c in p.lower() if c.isalnum()), p))
total = hashlib.sha256()
for p in paths:
    content = git('cat-file', 'blob', blobs[p])
    total.update(f'{hashlib.sha256(content).hexdigest()}  {p}\n'.encode())
print(total.hexdigest(), len(paths), 'files')
