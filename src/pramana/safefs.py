"""File writes that cannot be redirected outside the folder they are meant for.

An audit pack, a key folder or a demo folder may have been prepared by someone else.
A symbolic link or hard link planted at a path Pramana writes could otherwise make it
overwrite, create or delete a file anywhere the user can write. Every write Pramana
makes into such a folder goes through this module, which:

* reaches sub-folders without following symbolic links, so a linked ``evidence/`` or
  stage folder is refused rather than followed;
* writes each file to a new temporary file beside it and renames it into place. A
  rename replaces the directory entry itself, so a symbolic link or hard link at the
  destination is never written through: the file it points to is left untouched;
* refuses to replace a destination that is a symbolic link, a folder or any other
  special file, so a prepared folder fails loudly instead of being silently "fixed".

The folder the user names (``--out``, ``--out-dir``) is trusted as given, including any
links in the path leading to it: only what is inside it is checked. On POSIX systems
the checks use directory file descriptors, so a link swapped in while Pramana is
running is refused as well. Windows has no such calls; there the same checks run on
paths (creating links there needs administrator rights or developer mode).
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_USE_DIR_FD = bool(_NOFOLLOW and _DIRECTORY) and all(
    f in os.supports_dir_fd for f in (os.open, os.mkdir, os.rename, os.unlink, os.stat)
)


class UnsafePathError(ValueError):
    """A path Pramana was about to write or delete is a link or not a regular file."""


def _parts(rel: str | Path) -> list[str]:
    """The components of a relative path; refuses absolute paths and '..'."""
    text = Path(rel).as_posix() if isinstance(rel, Path) else str(rel).replace("\\", "/")
    pure = PurePosixPath(text)
    parts = [p for p in pure.parts if p not in ("", ".")]
    if pure.is_absolute() or not parts or any(p == ".." for p in parts):
        raise UnsafePathError(f"not a plain relative path inside the folder: {rel}")
    return parts


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "a symbolic link"
    if stat.S_ISDIR(mode):
        return "a folder"
    return "not a regular file"


class _Dir:
    """An open folder: a descriptor on POSIX, a checked path elsewhere."""

    def __init__(self, path: Path, fd: int | None):
        self.path = path
        self.fd = fd

    def lstat(self, name: str) -> os.stat_result | None:
        try:
            if self.fd is not None:
                return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            return os.lstat(self.path / name)
        except FileNotFoundError:
            return None

    def names(self) -> list[str]:
        return sorted(os.listdir(self.fd if self.fd is not None else self.path))


def _open_child(parent: _Dir, name: str, create: bool, mode: int) -> _Dir:
    where = parent.path / name
    if parent.fd is not None:
        flags = os.O_RDONLY | _DIRECTORY | _NOFOLLOW
        try:
            return _Dir(where, os.open(name, flags, dir_fd=parent.fd))
        except FileNotFoundError:
            if not create:
                raise
        except OSError as exc:  # ELOOP / ENOTDIR: a link or a file where a folder should be
            st = parent.lstat(name)
            what = _kind(st.st_mode) if st else "not a folder"
            raise UnsafePathError(f"{where} is {what}; refusing to use it") from exc
        os.mkdir(name, mode, dir_fd=parent.fd)
        try:
            return _Dir(where, os.open(name, flags, dir_fd=parent.fd))
        except OSError as exc:  # replaced by a link between mkdir and open
            raise UnsafePathError(f"{where} changed while it was being created") from exc
    st = parent.lstat(name)
    if st is None:
        if not create:
            raise FileNotFoundError(where)
        os.mkdir(where, mode)
        st = os.lstat(where)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise UnsafePathError(f"{where} is {_kind(st.st_mode)}; refusing to use it")
    return _Dir(where, None)


@contextmanager
def open_dir(
    root: str | Path, rel: str | Path | None = None, *, create: bool = True, mode: int = 0o755
) -> Iterator[_Dir]:
    """Open ``root/rel``. ``root`` is trusted as given; each folder below it must be a real
    folder (not a link), and is created when missing if ``create`` is set."""
    root = Path(root)
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=mode)
    current = _Dir(root, os.open(root, os.O_RDONLY | _DIRECTORY) if _USE_DIR_FD else None)
    try:
        for name in _parts(rel) if rel not in (None, "", ".") else []:
            child = _open_child(current, name, create, mode)
            if current.fd is not None:
                os.close(current.fd)
            current = child
        yield current
    finally:
        if current.fd is not None:
            os.close(current.fd)


def check_replaceable(folder: _Dir, name: str) -> None:
    """Refuse a destination that exists and is not a regular file."""
    st = folder.lstat(name)
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise UnsafePathError(
            f"{folder.path / name} is {_kind(st.st_mode)}; refusing to replace it"
        )


def _write_temp(folder: _Dir, name: str, data: bytes, mode: int, durable: bool) -> str:
    """Write ``data`` to a new, exclusively created file next to ``name``."""
    tmp = f".{name}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY
    if folder.fd is not None:
        fd = os.open(tmp, flags, mode, dir_fd=folder.fd)
    else:
        fd = os.open(folder.path / tmp, flags, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        if durable:
            os.fsync(fd)
    except BaseException:
        os.close(fd)
        _unlink_quietly(folder, tmp)
        raise
    os.close(fd)
    return tmp


def _rename(folder: _Dir, src: str, dst: str) -> None:
    if folder.fd is not None:
        os.rename(src, dst, src_dir_fd=folder.fd, dst_dir_fd=folder.fd)
    else:
        os.replace(folder.path / src, folder.path / dst)


def _unlink_quietly(folder: _Dir, name: str) -> None:
    try:
        if folder.fd is not None:
            os.unlink(name, dir_fd=folder.fd)
        else:
            os.unlink(folder.path / name)
    except OSError:
        pass


def replace_file(folder: _Dir, name: str, data: bytes, *, mode: int = 0o644, durable=False):
    """Atomically put ``data`` at ``folder/name`` as a new file."""
    check_replaceable(folder, name)
    tmp = _write_temp(folder, name, data, mode, durable)
    try:
        check_replaceable(folder, name)
        _rename(folder, tmp, name)
    except BaseException:
        _unlink_quietly(folder, tmp)
        raise


def write_bytes(root: str | Path, rel: str | Path, data: bytes, *, mode: int = 0o644) -> Path:
    """Write ``root/rel`` safely (see the module docstring). Returns the path written."""
    parts = _parts(rel)
    with open_dir(root, "/".join(parts[:-1]) or None) as folder:
        replace_file(folder, parts[-1], data, mode=mode)
        return folder.path / parts[-1]


def write_text(root: str | Path, rel: str | Path, text: str, *, mode: int = 0o644) -> Path:
    return write_bytes(root, rel, text.encode("utf-8"), mode=mode)


def write_user_file(path: str | Path, data: bytes | str) -> Path:
    """Write a file the user named on the command line (``--out``), atomically and never
    through a symbolic link already at that path."""
    path = Path(path)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return write_bytes(path.parent, path.name, payload)


def append_bytes(root: str | Path, rel: str | Path, data: bytes) -> None:
    """Append to an existing regular file inside ``root``, never through a link."""
    parts = _parts(rel)
    with open_dir(root, "/".join(parts[:-1]) or None, create=False) as folder:
        flags = os.O_WRONLY | os.O_APPEND | _NOFOLLOW | _BINARY
        try:
            if folder.fd is not None:
                fd = os.open(parts[-1], flags, dir_fd=folder.fd)
            else:
                check_replaceable(folder, parts[-1])
                fd = os.open(folder.path / parts[-1], flags)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise UnsafePathError(f"{folder.path / parts[-1]} is not a regular file") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise UnsafePathError(f"{folder.path / parts[-1]} is not a regular file")
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
        finally:
            os.close(fd)


def read_bytes(root: str | Path, rel: str | Path) -> bytes:
    """Read a regular file inside ``root`` without following links."""
    parts = _parts(rel)
    with open_dir(root, "/".join(parts[:-1]) or None, create=False) as folder:
        flags = os.O_RDONLY | _NOFOLLOW | _BINARY
        try:
            if folder.fd is not None:
                fd = os.open(parts[-1], flags, dir_fd=folder.fd)
            else:
                check_replaceable(folder, parts[-1])
                fd = os.open(folder.path / parts[-1], flags)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise UnsafePathError(f"{folder.path / parts[-1]} is not a regular file") from exc
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise UnsafePathError(f"{folder.path / parts[-1]} is not a regular file")
            return handle.read()


def remove_file(folder: _Dir, name: str) -> bool:
    """Delete ``folder/name`` if it is a regular file or a link (removing a link never
    touches what it points to). Refuses folders and special files."""
    st = folder.lstat(name)
    if st is None:
        return False
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
        raise UnsafePathError(f"{folder.path / name} is {_kind(st.st_mode)}; refusing to delete it")
    if folder.fd is not None:
        os.unlink(name, dir_fd=folder.fd)
    else:
        os.unlink(folder.path / name)
    return True
