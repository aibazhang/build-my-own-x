import re
import os
import sys
import argparse
import configparser
import zlib
import hashlib
import collections

argparser = argparse.ArgumentParser(description="The stupidest content tracker")
argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
argsubparsers.required = True


def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)

    if args.command == "add":
        cmd_add(args)
    elif args.command == "cat-file":
        cmd_cat_file(args)
    elif args.command == "checkout":
        cmd_checkout(args)
    elif args.command == "commit":
        cmd_commit(args)
    elif args.command == "hash-object":
        cmd_hash_object(args)
    elif args.command == "init":
        cmd_init(args)
    elif args.command == "log":
        cmd_log(args)
    elif args.command == "ls-files":
        cmd_ls_files(args)
    elif args.command == "ls-tree":
        cmd_ls_tree(args)
    elif args.command == "merge":
        cmd_merge(args)
    elif args.command == "rebase":
        cmd_rebase(args)
    elif args.command == "rev-parse":
        cmd_rev_parse(args)
    elif args.command == "rm":
        cmd_rm(args)
    elif args.command == "show-ref":
        cmd_show_ref(args)
    elif args.command == "tag":
        cmd_tag(args)


"""
3. Creating repositories: init
"""


class GitRepository(object):
    """A git repository"""

    worktree = None
    gitdir = None
    conf = None

    def __init__(self, path, force=False) -> None:
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")

        if not (force or os.path.isdir(self.gitdir)):
            raise Exception(f"Not a Git repository {path}")

        # Read configuration file
        self.conf = configparser.ConfigParser()
        cf = repo_file(self, "config")

        if cf and os.path.exists(cf):
            self.conf.read([cf])
        elif not force:
            raise Exception("Configuration file missing")

        if not force:
            vers = int(self.conf.get("core", "repositoryformatversion"))
            if vers != 0:
                raise Exception(f"Unsupported respositoryformatversion {vers}")


# utility functions to compute those paths and create missing directroy structures if needed
def repo_path(repo: GitRepository, *path):
    """Compute path under repo's gitdir"""
    return os.path.join(repo.gitdir, *path)


def repo_file(repo: GitRepository, *path, mkdir=False):
    """
    Same as repo_path, but crate dirname(*path)
    """
    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)


def repo_dir(repo: GitRepository, *path, mkdir=False):
    """
    Same as repo_path, but mkdir *path if absent if mkidr
    """
    path = repo_path(repo, *path)

    if os.path.exists(path):
        if os.path.isdir(path):
            return path
        else:
            raise Exception(f"Not a directory {path}")

    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None


def repo_create(path):
    """
    Create a new repository at path.
    """
    repo = GitRepository(path, True)

    # First, we make sure the path either doesn't exist or is an empty dir.

    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception(f"{path} is not a directory")
        if os.listdir(repo.worktree):
            raise Exception(f"{path} is not empty")
    else:
        os.makedirs(repo.worktree)

    assert repo_dir(repo, "branches", mkdir=True)
    assert repo_dir(repo, "objects", mkdir=True)
    assert repo_dir(repo, "refs", "tags", mkdir=True)
    assert repo_dir(repo, "refs", "heads", mkdir=True)

    # .git/description
    with open(repo_file(repo, "description"), "w") as f:
        f.write(
            "Unnamed repository: edit this file 'description' to name the repository\n"
        )

    # .git/HEAD
    with open(repo_file(repo, "HEAD"), "w") as f:
        f.write("ref: refs/heads/master\n")

    with open(repo_file(repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)

    return repo


def repo_default_config():
    ret = configparser.ConfigParser()

    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret


def repo_find(path=".", required=True):
    path = os.path.realpath(path)
    if os.path.isdir(os.path.join(path, ".git")):
        return GitRepository(path)

    # If we haven't return, recurse in parent
    parent = os.path.realpath(os.path.join(path, ".."))

    if parent == path:
        if required:
            raise Exception("No git directory")
        else:
            return None

    # Recursive case
    return repo_find(parent, required)


argsp = argsubparsers.add_parser("init", help="Initialize a new. empty repository")
argsp.add_argument(
    "path",
    metavar="directory",
    nargs="?",
    default=".",
    help="Where to create the repository",
)


def cmd_init(args):
    repo_create(args.path)


"""
4. Reading and writing objects: hash-object and cat-file
"""


class GitObject(object):
    repo = None

    def __init__(self, repo, data=None) -> None:
        self.repo = repo
        if data is not None:
            self.deserialize(data)

    def serialize(self):
        """
        This function MUST be implemented by subclasses

        It must read the object's contents from self.data. a byte string, and do
        whatever it takes to convert it into a meaningful representation.
        What exactly that means depend on each subclass.
        """
        raise Exception("Unimplemented!")

    def deserialize(self):
        raise Exception("Unimplemented!")


def object_read(repo, sha):
    """
    Read object object_id from Git repository repo.
    Return a GitObject whose exact type depends on the object.
    """
    path = repo_file(repo, "objects", sha[0:2], sha[2:])

    with open(path, "rb") as f:
        raw = zlib.decompress(f.read())

        # Read object type
        x = raw.find(b" ")
        fmt = raw[0:x]

        # Read and validate object size
        y = raw.find(b"\x00", x)
        size = int(raw[x:y].decode("ascii"))
        if size != len(raw) - y - 1:
            raise Exception(f"Malformed object {sha}: bad length")

        # Pick constructor
        if fmt == b"commit":
            c = GitCommit
        elif fmt == b"tree":
            c = GitTree
        elif fmt == b"tag":
            c = GitTag
        elif fmt == b"blob":
            c = GitBlob
        else:
            raise Exception(f"Unknown type {fmt.decode('ascii')} for object {sha}")

        return c(repo, raw[y + 1 :])


def object_find(repo, name, fmt=None, follow=True):
    sha = object_resolve(repo, name)

    if not sha:
        raise Exception("No such reference {0}.".format(name))

    if len(sha) > 1:
        raise Exception(
            "Ambiguous reference {0}: Candidates are:\n - {1}.".format(
                name, "\n - ".join(sha)
            )
        )

    sha = sha[0]

    if not fmt:
        return sha

    while True:
        obj = object_read(repo, sha)

        if obj.fmt == fmt:
            return sha

        if not follow:
            return None

        # Follow tags
        if obj.fmt == b"tag":
            sha = obj.kvlm[b"object"].decode("ascii")
        elif obj.fmt == b"commit" and fmt == b"tree":
            sha = obj.kvlm[b"tree"].decode("ascii")
        else:
            return None


def object_write(obj, actually_write=True):
    # Serialize object data
    data = obj.serialize()
    # Add header
    result = obj.fmt + b" " + str(len(data)).encode() + b"\x00" + data
    # Compute hash
    sha = hashlib.sha1(result).hexdigest()

    if actually_write:
        # Compute path
        path = repo_file(obj.repo, "objects", sha[0:2], sha[2:], mkdir=actually_write)

        with open(path, "wb") as f:
            # Compress and write
            f.write(zlib.compress(result))

    return sha


class GitBlob(GitObject):
    fmt = b"blob"

    def serialize(self):
        return self.blobdata

    def deserialize(self, data):
        self.blobdata = data


argsp = argsubparsers.add_parser(
    "cat-file", help="Provide content of repository objects"
)

argsp.add_argument(
    "type",
    metavar="type",
    choices=["blob", "commit", "tag", "tree"],
    help="Spcify the type",
)
argsp.add_argument("object", metavar="object", help="The object to display")


def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())


def cat_file(repo, obj, fmt=None):
    obj = object_read(repo, object_find(repo, obj, fmt=fmt))
    sys.stdout.buffer.write(obj.serialize())


argsp = argsubparsers.add_parser(
    "hash-object", help="Compute object ID and optionally creates a blob from a file"
)
argsp.add_argument(
    "-t",
    metavar="type",
    dest="type",
    choices=["blob", "commit", "tag", "tree"],
    default="blob",
    help="Specify the type",
)

argsp.add_argument(
    "-w",
    dest="write",
    action="store_true",
    help="Actually write the object into the database",
)

argsp.add_argument("path", help="Read object from <file>")


def cmd_hash_object(args):
    if args.write:
        repo = GitRepository(".")
    else:
        repo = None

    with open(args.path, "rb") as fd:
        sha = object_hash(fd, args.type.encode(), repo)
        print(sha)


def object_hash(fd, fmt, repo=None):
    data = fd.read()

    # Choose constructor depending on
    # object type found in header
    if fmt == b"commit":
        obj = GitCommit(repo, data)
    elif fmt == b"tree":
        obj = GitTree(repo, data)
    elif fmt == b"tag":
        obj = GitTag(repo, data)
    elif fmt == b"blob":
        obj = GitBlob(repo, data)
    else:
        raise Exception("Unknown type %s!" % fmt)

    return object_write(obj, repo)


"""
5. Reading commit history: log
"""


# KVLM: Key-Vakye List with Message
def kvlm_parse(raw: str, start=0, dct=None):
    if not dct:
        dct = collections.OrderedDict()
        # You CANNOT declare the argument as dct=OrderedDict() or all
        # call the functions will endlessly grow the same dict.

    # We search for the next space and the next newline
    spc = raw.find(b" ", start)
    nl = raw.find(b"\n", start)

    # If space appears before newline, we have a keyword

    # Base case
    # =========
    # If newline appears first (or there's no space at all, in which
    # case find returns -1). we assume a blank line. A black line
    # means the remainder of the data is the message

    if spc < 0 or nl < spc:
        assert nl == start
        dct[b""] = raw[start + 1 :]
        return dct

    # Recursive case
    # =========
    # we read a key-value pair and recurse for the next
    key = raw[start:spc]

    # Find the end of the value. Continuation lines begin with a
    # space. so we loop until we find a "\n" not followed by a space.
    end = start
    while True:
        end = raw.find(b"\n", end + 1)
        if raw[end + 1] != ord(" "):
            break

    # Grab the value
    # Also, drop the leading space on continuation lines
    value = raw[spc + 1 : end].replace(b"\n ", b"\n")

    # Don't overwrite existing data contents
    if key in dct:
        if type(dct[key]) == list:
            dct[key].append(value)
        else:
            dct[key] = [dct[key], value]
    else:
        dct[key] = value

    return kvlm_parse(raw, start=end + 1, dct=dct)


def kvlm_serialize(kvlm: dict):
    ret = b""

    # Output fields
    for k, val in kvlm.items():
        # Skip the message itself
        if k == b"":
            continue
        # Normalize to a list
        if type(val) != list:
            val = [val]
        for v in val:
            ret += k + b" " + (v.replace(b"\n", b"\n ")) + b"\n"

    # Append message
    ret += b"\n" + kvlm[b""]

    return ret


class GitCommit(GitObject):
    fmt = b"commit"

    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)

    def serialize(self):
        return kvlm_serialize(self.kvlm)


argsp = argsubparsers.add_parser("log", help="Display history of a given commit.")
argsp.add_argument("commit", default="HEAD", nargs="?", help="Commit to start at.")


def cmd_log(args):
    repo = repo_find()
    print("digraph wyaglog{")
    log_graphviz(repo, object_find(repo, object_find(repo, args.commit)), set())


def log_graphviz(repo, sha, seen):
    if sha in seen:
        return
    seen.add(sha)

    commit: GitCommit = object_read(repo, sha)
    assert commit.fmt == b"commit"

    if b"parent" not in commit.kvlm[b"parent"]:
        # Base case: the initial commit
        return
    parents = commit.kvlm[b"parent"]

    if type(parents) != list:
        parents = [parents]

    for p in parents:
        p = p.decode("ascii")
        print(f"c_{sha} -> c_{p}")
        log_graphviz(repo, p, seen)


"""
6. Reading commit data: checkout
"""


class GitTreeLeaf(object):
    def __init__(self, mode, path, sha) -> None:
        self.mode = mode
        self.path = path
        self.sha = sha


def tree_parse_one(raw, start=0):
    # Find the space terminator of the mode
    x = raw.find(b" ", start)
    assert x - start == 5 or x - start == 6

    # Read the mode
    mode = raw[start:x]

    # Find the NULL termminator of the path
    y = raw.find(b"\x00", x)
    # and read the path
    path = raw[x + 1 : y]

    # Read the SHA and convert to an hex string
    # hex() adds 0x in front we don't want that
    sha = hex(int.from_bytes(raw[y + 1 : y + 21], "big"))[2:]

    return y + 21, GitTreeLeaf(mode, path, sha)


def tree_parse(raw):
    pos = 0
    max = len(raw)
    ret = list()

    while pos < max:
        pos, data = tree_parse_one(raw, pos)
        ret.append(data)

    return ret


def tree_serialize(obj):
    ret = b""
    for i in obj.items:
        ret += i.mode
        ret += b" "
        ret += i.path
        ret += b"\x00"
        sha = int(i.sha, 16)
        ret += sha.to_bytes(20, byteorder="big")
    return ret


class GitTree(GitObject):
    fmt = b"tree"

    def deserialize(self, data):
        self.items = tree_parse(data)

    def serialize(self):
        return tree_serialize(self)


argsp = argsubparsers.add_parser("ls-tree", help="Pretty-print a tree object")
argsp.add_argument("object", help="The object to show.")


def cmd_ls_tree(args):
    repo = repo_find()
    obj = object_read(repo, object_find(repo, args.object, fmt=b"tree"))

    for item in obj.items:
        print(
            "{0} {1} {2}\t{3}".format(
                "0" * (6 - len(item.mode)) + item.mode.decode("ascii"),
                # Git's ls-tree displays the type
                # of the object pointed to.  We can do that too :)
                object_read(repo, item.sha).fmt.decode("ascii"),
                item.sha,
                item.path.decode("ascii"),
            )
        )


argsp = argsubparsers.add_parser(
    "checkout", help="Checkout a commit inside of a directory."
)

argsp.add_argument("commit", help="The commit or tree to checkout.")

argsp.add_argument("path", help="The EMPTY directory to checkout on.")


def cmd_checkout(args):
    repo = repo_find()

    obj = object_read(repo, object_read(repo, args.commit))

    # If the object is a commit, we grab its tree
    if obj.fmt == b"commit":
        obj = object_read(repo, obj.kvlm[b"tree"].decode("ascii"))

    # Verify that path is an empty directory
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception("Not a directory {0}!".format(args.path))
        if os.listdir(args.path):
            raise Exception("Not empty {0}!".format(args.path))

    else:
        os.makedirs(args.path)

    tree_checkout(repo, obj, os.path.realpath(args.path).encode())


def tree_checkout(repo, tree, path):
    for item in tree.items:
        obj = object_read(repo, item.sha)
        dest = os.path.join(path, item.path)

        if obj.fmt == b"tree":
            os.mkdir(dest)
            tree_checkout(repo, obj, dest)
        elif obj.fmt == b"blob":
            with open(dest, "wb") as f:
                f.write(obj.blobdata)


"""
7. Refs, tags and branches
"""


def ref_resolve(repo, ref):
    with open(repo_file(repo, ref), "r") as fp:
        data = fp.read()[:-1]
        # Drop final \n ^^^^^
    if data.startswith("ref: "):
        return ref_resolve(repo, data[5:])
    else:
        return data


def ref_list(repo, path=None):
    if not path:
        path = repo_dir(repo, "refs")
    ret = collections.OrderedDict()

    # Git shows refs sorted. To do the same, we use
    # an OrderedDict and sort the ouput of listdir
    for f in sorted(os.listdir(path)):
        can = os.path.join(path, f)
        if os.path.isdir(can):
            ret[f] = ref_list(repo, can)
        else:
            ret[f] = ref_resolve(repo, can)
    return ret


argsp = argsubparsers.add_parser("show-ref", help="List references.")


def cmd_show_ref(args):
    repo = repo_find()
    refs = ref_list(repo)
    show_ref(repo, refs, prefix="refs")


def show_ref(repo, refs, with_hash=True, prefix=""):
    for k, v in refs.items():
        if type(v) == str:
            print(
                "{0}{1}{2}".format(
                    v + " " if with_hash else "", prefix + "/" if prefix else "", k
                )
            )
        else:
            show_ref(
                repo,
                v,
                with_hash=with_hash,
                prefix="{0}{1}{2}".format(prefix, "/" if prefix else "", k),
            )


class GitTag(GitCommit):
    fmt = b"tag"


argsp = argsubparsers.add_parser("tag", help="List and create tags")

argsp.add_argument(
    "-a",
    action="store_true",
    dest="create_tag_object",
    help="Whether to create a tag object",
)

argsp.add_argument("name", nargs="?", help="The new tag's name")

argsp.add_argument(
    "object", default="HEAD", nargs="?", help="The object the new tag will point to"
)


def cmd_tag(args):
    repo = repo_find()

    if args.name:
        tag_create(
            repo,
            args.name,
            args.object,
            type="object" if args.create_tag_object else "ref",
        )
    else:
        refs = ref_list(repo)
        show_ref(repo, refs["tags"], with_hash=False)


def tag_create(repo, name, reference, type):
    # Get the Gitobject form the object reference
    sha = object_find(repo, reference)

    if type == "object":
        # create tag object (commit)
        tag = GitTag(repo)
        tag.kvlm = collections.OrderedDict()
        tag.kvlm[b"object"] = sha.encode()
        tag.kvlm[b"type"] = b"commit"
        tag.kvlm[b"tag"] = name.encode()
        # Feel free to let the user give their name!
        tag.kvlm[b"tagger"] = b"Way <wyag@example.com>"
        # _and a tag message!
        tag.kvlm[
            b""
        ] = b"A tag generated by wyag. which won't let you customize the message!"
        tag_sha = object_write(tag, repo)
        # create reference
        ref_create(repo, "tags/" + name, tag_sha)

    else:
        # create lightweight tag (ref)
        ref_create(repo, "tags/" + name, sha)


def ref_create(repo, ref_name, sha):
    with open(repo_file(repo, "refs/" + ref_name), "w") as fp:
        fp.write(sha + "\n")


def object_resolve(repo, name):
    """Resolve name to an object hash in repo

    This function is aware of
    - the HEAD literal
    - short and long hashes
    - tags
    - branches
    - remote branches
    """
    candidates = list()
    hashRE = re.compile(r"^[0-9A-Fa-f]{4,40}")

    if not name.strip():
        return None

    # Head is nonambiguous
    if name == "HEAD":
        return [ref_resolve(repo, "HEAD")]

    if hashRE.match(name):
        if len(name) == 40:
            # This is a complete hash
            return [name.lower()]

        # This is a small hash 4 seems to be the minimal length
        name = name.lower()
        prefix = name[0:2]
        path = repo_dir(repo, "objects", prefix, mkdir=False)
        if path:
            rem = name[2:]
            for f in os.listdir(path):
                if f.startswith(rem):
                    candidates.append(prefix + f)
    return candidates


argsp = argsubparsers.add_parser(
    "rev-parse", help="Parse revision (or other objects )identifiers"
)

argsp.add_argument(
    "--wyag-type",
    metavar="type",
    dest="type",
    choices=["blob", "commit", "tag", "tree"],
    default=None,
    help="Specify the expected type",
)

argsp.add_argument("name", help="The name to parse")


def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None

    repo = repo_find()

    print(object_find(repo, args.name, fmt, follow=True))


"""
8. The staging area and the index file
"""
