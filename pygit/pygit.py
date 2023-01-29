import argparse
import sys
import os
import hashlib
import zlib
import enum
import stat
import collections
import struct
import difflib

from pathlib import Path


class ObjectType(enum.Enum):
    commit = 1
    tree = 2
    blob = 3


# Data for one entry in the git index (.git/index)
IndexEntry = collections.namedtuple(
    "IndexEntry",
    [
        "ctime_s",
        "ctime_n",
        "mtime_s",
        "mtime_n",
        "dev",
        "ino",
        "mode",
        "uid",
        "gid",
        "size",
        "sha1",
        "flags",
        "path",
    ],
)


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def init(repo: str):
    """Create directory for repo and initialize .git directory."""
    Path(repo).mkdir()
    Path(f"{repo}/.git").mkdir()
    for name in ["objects", "refs", "refs/heads"]:
        Path(f"{repo}/.git/{name}").mkdir()

    Path(f"{repo}/.git/HEAD").touch()
    write_file(Path(f"{repo}/.git/HEAD"), b"ref: refs/heads/master")
    print(f"initialized empty repository: {repo}")


def hash_object(data: str, obj_type: str, write: bool = True) -> str:
    """Compute has of object data of given type and write to object store
    if "write" is True. Return SHA-1 object has as hex string
    """
    header = f"{obj_type} {len(data)}".encode()
    full_data = header + b"\x00" + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    if write:
        path = os.path.join(".git", "objects", sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))
    return sha1


def find_object(sha1_prefix: str) -> str:
    """Find object with given SHA-1 prefix and return path to object in object store,
    or raise ValueError if there are no objects or multiple objects with this prefix
    """
    if len(sha1_prefix) < 2:
        raise ValueError("hash prefix must be 2 or more characters")

    obj_dir = os.path.join(".git", "objects", sha1_prefix[:2])
    rest = sha1_prefix[2:]
    objects = [name for name in os.listdir(obj_dir) if name.startswith(rest)]
    if not objects:
        raise ValueError(f"object {sha1_prefix} not found")
    if len(objects) >= 2:
        raise ValueError(f"multiple objects ({len(objects)}) with prefix {sha1_prefix}")

    return os.path.join(obj_dir, objects[0])


def read_object(sha1_prefix: str) -> tuple[str, bytes]:
    """Read object with given SHA-1 prefix and return tuple of
    (object_tyoe, data_byetes), or raise ValueError if not found.
    """
    path = find_object(sha1_prefix)
    full_data = zlib.decompress(read_file(path))
    nul_index = full_data.index(b"\x00")
    header = full_data[:nul_index]
    obj_type, size_str = header.decode().split()
    size = int(size_str)
    data = full_data[nul_index + 1 :]
    if size != len(data):
        raise ValueError(f"expected size {size}, but got {len(data)} bytes")
    return (obj_type, data)


def cat_file(mode: str, sha1_prefix: str):
    """Write the contents of (or info about) object with given SHA-1 prefix to stdout.
    If mode is 'commit', 'tree', or 'blob', print raw data bytes of object.
    If mode is 'size' print the size of the object.
    If mode is 'type', print the type of the object.
    If mode is 'pretty' print a prettified version of the object"""

    obj_type, data = read_object(sha1_prefix)
    if mode in ["commit", "tree", "blob"]:
        if obj_type != mode:
            raise ValueError(f"expected object type {mode}, got {obj_type}")
        sys.stdout.buffer.write(data)

    elif mode == "size":
        print(len(data))
    elif mode == "type":
        print(obj_type)
    elif mode == "pretty":
        if obj_type in ["commit", "blob"]:
            sys.stdout.buffer.write(data)
        elif obj_type == "tree":
            for mode, path, sha1 in read_tree(data=data):
                type_str = "tree" if stat.S_ISDIR(mode) else "blob"
                print("{:06o} {} {}\t{}".format(mode, type_str, sha1, path))
        else:
            assert False, "unhandled object type {!r}".format(obj_type)
    else:
        raise ValueError("unexpected mode {!r}".format(mode))


def read_index() -> list[IndexEntry]:
    """Read git index file and return list of IndexEntry objects."""
    try:
        data = read_file(os.path.join(".git", "index"))
    except FileNotFoundError:
        return []

    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[-20:], "invalid index checksum"
    signature, version, num_entries = struct.unpack("!4sLL", data[:12])
    assert signature == b"DIRC", f"invalid index signature {signature}"
    assert version == 2, f"unkown index version {version}"
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
        fields_end = i + 62
        fields = struct.unpack("!LLLLLLLLLL20sH", entry_data[i:fields_end])
        path_end = entry_data.index(b"\x00", fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    assert len(entries) == num_entries
    return entries


def ls_files(details: bool = False):
    """Print list of files in index (including mode,
    SHA-1 and stage number if "details" is True"""
    for entry in read_index():
        if details:
            stage = (entry.flags >> 12) & 3
            print(f"{entry.mode} {entry.sha1.hex()} {stage} {entry.path}")
        else:
            print(entry.path)


def get_status() -> tuple[set, set, set]:
    """Get status of working copy, return tuple of (changed_path,
    new_paths, deleted_paths)"""
    paths = set()
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d != ".git"]
        for file in files:
            path = os.path.join(root, file)
            path = path.replace("\\", "/")
            if path.startswith("./"):
                path = path[2:]
            paths.add(path)
    entries_by_path = {e.path: e for e in read_index()}
    entry_paths = set(entries_by_path)

    changed = {
        p
        for p in (paths & entry_paths)
        if hash_object(read_file(p), "blob", write=False)
        != entries_by_path[p].sha1.hex()
    }
    new = paths - entry_paths
    deleted = entry_paths - paths

    return sorted(changed), sorted(new), sorted(deleted)


def status():
    """Show status of working copy."""
    changed, new, deleted = get_status()
    if changed:
        print("changed files:")
        for path in changed:
            print("   ", path)
    if new:
        print("new files:")
        for path in new:
            print("   ", path)
    if deleted:
        print("deleted files:")
        for path in deleted:
            print("   ", path)


def diff():
    """Show diff of files changed (between index and working copy)."""
    changed, _, _ = get_status()
    entries_by_path = {e.path: e for e in read_index()}
    for i, path in enumerate(changed):
        sha1 = entries_by_path[path].sha1.hex()
        obj_type, data = read_object(sha1)
        assert obj_type == "blob"
        index_lines = data.decode().splitlines()
        working_lines = read_file(path).decode().splitlines()
        diff_lines = difflib.unified_diff(
            index_lines, working_lines, f"{path} (index)", f"{path} (working copy)"
        )
        for line in diff_lines:
            print(line)
        if i < len(changed) - 1:
            print("-" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub_parsers = parser.add_subparsers(dest="command", metavar="command")
    sub_parsers.required = True

    sub_parser = sub_parsers.add_parser("init", help="initialize a new repo")
    sub_parser.add_argument("repo", help="directory name for new repo")

    sub_parser = sub_parsers.add_parser(
        "hash-object",
        help="has contents of given path (and optionally write to object store)",
    )
    sub_parser.add_argument("path", help="path of file to hash")
    sub_parser.add_argument(
        "-t",
        choices=["commit", "tree", "blob"],
        default="blob",
        dest="type",
        help="type of object (default %(default)r)",
    )
    sub_parser.add_argument(
        "-w",
        action="store_true",
        dest="write",
        help="write object to object store (as well as printing hash)",
    )

    sub_parser = sub_parsers.add_parser("ls-files", help="list files in index")
    sub_parser.add_argument(
        "-s",
        "--stage",
        action="store_true",
        help="show object details (mode, hash, and stage number) in "
        "addition to path",
    )

    sub_parser = sub_parsers.add_parser("status", help="show status of working copy")

    sub_parser = sub_parsers.add_parser(
        "diff", help="show diff of files changed (between index and working " "copy)"
    )

    args = parser.parse_args()
    if args.command == "add":
        pass
    elif args.command == "init":
        init(args.repo)
    elif args.command == "hash-object":
        sha1 = hash_object(read_file(args.path), args.type, write=args.write)
        print(sha1)
    elif args.command == "ls-files":
        ls_files(details=args.stage)
    elif args.command == "status":
        status()
    elif args.command == "diff":
        diff()

    # read index ????
