#!/usr/bin/env python3
import sys, os, subprocess

usage="""
Usage:
	./export-header.py <path/to/header/file>
"""

if len(sys.argv) != 2:
	print(usage)
	sys.exit(0)

tools_dir = os.path.dirname(os.path.realpath(__file__))
root_dir = os.path.dirname(tools_dir)
os.chdir(root_dir)

fn = sys.argv[1].strip()

if not fn.endswith('.h'):
	print('must be a header file (*.h)')
	sys.exit(-1)

if not os.path.isfile(fn):
	print('must exist as a regular file')
	sys.exit(-1)

fn = os.path.abspath(fn)
if not '/PhotonLibOS/' in fn:
	print('must be a header file of photon')
	sys.exit(-1)

parts = fn.split('/')
i = parts.index('PhotonLibOS') + 1
photon = '/'.join(parts[:i])
file = parts[i:]
include = photon + '/include/photon/'
if not os.path.isdir(include):
	print('it must exist as a directory:', include)

target = '../../'
path = os.path.relpath(include) + '/'
for dir in file[:-1]:
	target += '../'
	path = path + dir + '/'
	if not os.path.exists(path):
		print('mkdir', path)
		os.makedirs(path)
	elif not os.path.isdir(path):
		print('path component conflicts:', path)
		os.exit(-1)

symlink = path + file[-1]

# The header's self-containment guard, next to the source that implements it: one
# #include of the exported name and nothing else. It is compiled as a source of the
# module that implements the header (see the photon_module() call in CMakeLists.txt).
guard = os.path.join(os.path.dirname(fn), 'guard-' + os.path.basename(fn) + '.cpp')
guard = os.path.relpath(guard)

# Both halves present: nothing left to do, and nothing to stage either.
if os.path.exists(symlink) or os.path.exists(guard):
	print('already exported:', symlink, 'or', guard)
	sys.exit(-1)

file = '/'.join(file)
target += file
print('symlink:', symlink, '->', target)
os.symlink(target, symlink)

with open(guard, 'w') as f:
	f.write('#include <photon/%s>\n' % file)
print('guard:', guard)

# All three go in together: the header, the symlink that names it, and the guard that
# proves it compiles. Leaving any one of them unstaged ships a broken export.
subprocess.run(['git', 'add', os.path.relpath(fn), symlink, guard], check=True)
