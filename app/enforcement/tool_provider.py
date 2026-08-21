"""Governed filesystem tool implementations executed behind the MCP proxy.

The MCP enforcement proxy authorizes tool + path scope before this handler runs;
the handler adds a second containment check against a workspace root so a
directly-issued or refreshed capsule can perform useful, in-scope file work.

Tools without a safe governed implementation (shell/network) are reported
explicitly rather than executed, so a locked-down agent never runs arbitrary
commands or outbound requests through the governed surface.

Closing the TOCTOU window
--------------------------
``_resolve()`` performs a *lexical* authorization check: it calls
``Path.resolve()`` to dereference any symlinks in the requested path and
verifies the result stays within the workspace root and the capsule's target
paths. That check reflects the filesystem's state at the moment it runs --
between that check returning and the eventual ``open()``, an attacker (or a
concurrent, unrelated process) could replace any path component with a
symlink pointing outside the workspace, and a naive ``target.read_text()`` /
``target.write_text()`` would follow it.

On platforms that support ``dir_fd`` (Linux/macOS -- including this project's
Docker deployment target), ``_secure_open_fd()`` closes that window: it walks
the path one component at a time, opening each directory relative to the
previous one's file descriptor with ``O_NOFOLLOW``, so the kernel atomically
rejects the open (``ELOOP``) if any component -- including ones created
after the authorization check ran -- turns out to be a symlink. There is no
re-lookup by path string after the walk begins, so there is no window left to
race. On platforms without ``dir_fd`` support (Windows), this falls back to
the previous pathlib-based behavior, which is still protected by the
lexical check above but remains theoretically racy; see
docs/known-limitations.md.
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path
from typing import Any

from app.enforcement.scope_checker import path_allowed
from app.models import KnownTools, SignedCapsule


logger = logging.getLogger(__name__)

_UNSUPPORTED = {"execute_cmd", "run_tests"}

# True on Linux/macOS (including the python:3.11-slim container this project
# deploys to); False on Windows, where os.open()/os.mkdir() do not accept a
# dir_fd argument at all.
_SECURE_OPEN_SUPPORTED = {os.open, os.mkdir}.issubset(os.supports_dir_fd)

_DEFAULT_FILE_MODE = 0o644


class GovernedToolHandler:
    """Perform in-scope file operations after the proxy has authorized a call."""

    def __init__(self, workspace_root: str | Path = ".") -> None:
        self._root = Path(workspace_root).resolve()

    def __call__(self, request: dict[str, Any], connection_id: str, capsule: SignedCapsule) -> dict[str, Any]:
        _ = connection_id
        params = request.get("params", {}) if isinstance(request, dict) else {}
        name = params.get("name")
        arguments = params.get("arguments") or {}

        if name == "read_file":
            return self._read_file(arguments, capsule)
        if name == "write_file":
            return self._write_file(arguments, capsule)
        if name == "net_request":
            return self._net_request(arguments, capsule)
        if name in _UNSUPPORTED:
            return {
                "ok": False,
                "tool": name,
                "error": f"'{name}' has no governed implementation in this handler",
            }
        return {"ok": False, "tool": name, "error": f"Unknown tool '{name}'"}

    def _resolve(self, raw_path: Any, capsule: SignedCapsule) -> Path:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValueError("a non-empty 'path' argument is required")
        candidate = (self._root / raw_path).resolve()
        if candidate != self._root and not candidate.is_relative_to(self._root):
            raise PermissionError(f"path escapes workspace root: {raw_path}")
        
        # Symlink re-validation: check the resolved path against capsule target paths
        relative_candidate = str(candidate.relative_to(self._root)).replace("\\", "/")
        if not path_allowed(relative_candidate, capsule.target_paths):
            raise PermissionError(f"resolved path '{relative_candidate}' is outside allowed target paths")
            
        return candidate

    def _secure_open_fd(self, relative_parts: list[str], *, for_write: bool) -> int:
        """Open the file at relative_parts (under self._root) without ever
        following a symlink at any path component, using a dir_fd walk.

        Each intermediate directory is opened with O_DIRECTORY | O_NOFOLLOW
        relative to the previous component's descriptor -- never by
        re-resolving a path string -- so a component swapped for a symlink
        at any point after _resolve() ran (the TOCTOU window) is rejected by
        the kernel (ELOOP for a symlinked leaf; empirically ENOTDIR on Linux
        for a symlinked intermediate directory opened with O_DIRECTORY --
        both are caught) instead of silently followed. For writes, missing
        intermediate directories are created, tolerating a benign creation
        race from a concurrent caller.

        Raises PermissionError if any component is a symlink, or OSError /
        FileNotFoundError for ordinary filesystem failures (propagated to the
        caller's existing error handling).
        """
        if not relative_parts:
            raise IsADirectoryError(f"'{self._root}' is a directory, not a file")

        *directories, leaf = relative_parts
        root_fd = os.open(str(self._root), os.O_RDONLY | os.O_DIRECTORY)
        try:
            dir_fd = root_fd
            owns_dir_fd = False

            for part in directories:
                try:
                    next_fd = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
                    )
                except FileNotFoundError:
                    if not for_write:
                        raise
                    try:
                        os.mkdir(part, dir_fd=dir_fd)
                    except FileExistsError:
                        pass  # lost a benign creation race -- fall through and open it
                    next_fd = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
                    )
                except OSError as exc:
                    # Linux raises ENOTDIR (not ELOOP) when O_NOFOLLOW|O_DIRECTORY
                    # hits a symlink -- confirmed empirically on the deployed
                    # kernel family; ELOOP is kept too since the flag
                    # combination's errno is not portable across platforms/
                    # kernel versions and this must fail closed either way.
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise PermissionError(
                            f"path component '{part}' is a symlink; refusing to follow"
                        ) from exc
                    raise

                if owns_dir_fd:
                    os.close(dir_fd)
                dir_fd = next_fd
                owns_dir_fd = True

            if for_write:
                leaf_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
            else:
                leaf_flags = os.O_RDONLY | os.O_NOFOLLOW

            try:
                leaf_fd = os.open(leaf, leaf_flags, _DEFAULT_FILE_MODE, dir_fd=dir_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise PermissionError(
                        f"path component '{leaf}' is a symlink; refusing to follow"
                    ) from exc
                raise
            finally:
                if owns_dir_fd:
                    os.close(dir_fd)

            return leaf_fd
        finally:
            os.close(root_fd)

    def _read_target(self, target: Path) -> str:
        if not _SECURE_OPEN_SUPPORTED:
            # Best-effort fallback: still protected by the lexical check in
            # _resolve(), but theoretically racy. See module docstring.
            return target.read_text(encoding="utf-8")
        parts = list(target.relative_to(self._root).parts)
        fd = self._secure_open_fd(parts, for_write=False)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read()

    def _write_target(self, target: Path, content: str) -> None:
        if not _SECURE_OPEN_SUPPORTED:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return
        parts = list(target.relative_to(self._root).parts)
        fd = self._secure_open_fd(parts, for_write=True)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)

    def _read_file(self, arguments: dict[str, Any], capsule: SignedCapsule) -> dict[str, Any]:
        try:
            target = self._resolve(arguments.get("path"), capsule)
            content = self._read_target(target)
        except (OSError, ValueError, PermissionError) as exc:
            return {"ok": False, "tool": "read_file", "error": str(exc)}
        return {"ok": True, "tool": "read_file", "path": str(target), "content": content}

    def _write_file(self, arguments: dict[str, Any], capsule: SignedCapsule) -> dict[str, Any]:
        content = arguments.get("content", "")
        try:
            if not isinstance(content, str):
                raise ValueError("'content' must be a string")
            target = self._resolve(arguments.get("path"), capsule)
            self._write_target(target, content)
        except (OSError, ValueError, PermissionError) as exc:
            return {"ok": False, "tool": "write_file", "error": str(exc)}
        return {
            "ok": True,
            "tool": "write_file",
            "path": str(target),
            "bytes_written": len(content.encode("utf-8")),
        }

    def _net_request(self, arguments: dict[str, Any], capsule: SignedCapsule) -> dict[str, Any]:  # noqa: PLR0911
        import ipaddress
        import socket
        import ssl
        import urllib.error
        import urllib.parse
        import urllib.request

        _MAX_REDIRECTS = 5

        def _validate_and_resolve(hostname: str) -> tuple[str, str]:
            """Resolve hostname via getaddrinfo (IPv4+IPv6), validate every address.

            Returns (validated_hostname, first_validated_ip_str).
            Raises ValueError if resolution fails or any address is private/reserved.
            Raises PermissionError if the hostname is not in the capsule allowlist.
            """
            # Allowlist check (case-insensitive).
            if hostname.lower() not in capsule.allowed_hosts:
                raise PermissionError(f"hostname '{hostname}' not in allowed_hosts")

            # If hostname is already a bare IP literal, validate it directly.
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast:
                    raise PermissionError("access to private/local/reserved IPs is blocked")
                return hostname, hostname
            except ValueError:
                pass  # not a bare IP literal — proceed to DNS resolution

            # DNS resolution — fail CLOSED on any error.
            try:
                results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except OSError as exc:
                # Resolution failed → fail closed.
                raise ValueError(f"DNS resolution failed for '{hostname}': {exc}") from exc

            if not results:
                raise ValueError(f"DNS resolution returned no addresses for '{hostname}'")

            validated_ip: str | None = None
            for family, _type, _proto, _canonname, sockaddr in results:
                raw_addr = sockaddr[0]
                try:
                    ip = ipaddress.ip_address(raw_addr)
                except ValueError:
                    raise ValueError(f"Unexpected address format from getaddrinfo: {raw_addr!r}")
                if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast:
                    raise PermissionError(
                        f"address '{raw_addr}' for '{hostname}' is private/local/reserved — blocked"
                    )
                if validated_ip is None:
                    validated_ip = raw_addr

            # validated_ip is set because results was non-empty and no early return/raise happened.
            return hostname, validated_ip  # type: ignore[return-value]

        def _make_pinned_opener(original_hostname: str, validated_ip: str) -> urllib.request.OpenerDirector:
            """Return an opener whose HTTPS handler connects to validated_ip instead of
            re-resolving the hostname — this pins the connection and defeats DNS rebinding.

            TLS certificate validation uses original_hostname (for SNI) so the certificate
            is still checked against the FQDN, not the raw IP address.
            """

            class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
                def https_open(self, req: urllib.request.Request):  # type: ignore[override]
                    host_header = req.host  # e.g. "example.com" or "example.com:443"
                    # urllib splits host:port — keep the port if present.
                    if ":" in host_header:
                        _host, port = host_header.rsplit(":", 1)
                        connect_host = f"{validated_ip}:{port}"
                    else:
                        connect_host = validated_ip
                    # Temporarily replace the host so urllib connects to the pinned IP.
                    req.host = connect_host  # type: ignore[assignment]
                    # Build a per-connection SSL context.
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = True
                    ctx.verify_mode = ssl.CERT_REQUIRED

                    import http.client as _http_client

                    def make_conn(h: str, **kw):
                        # connect_host is the IP:port — TCP goes to the pinned IP.
                        # server_hostname is the original FQDN — TLS/SNI checks use the hostname.
                        return _http_client.HTTPSConnection(
                            connect_host,
                            context=ctx,
                            server_hostname=original_hostname,
                            **kw,
                        )

                    result = self.do_open(make_conn, req, context=ctx)  # type: ignore[call-arg]
                    req.host = host_header  # restore for any subsequent redirect handling
                    return result

            # Build a minimal opener: NO redirect handler (we handle redirects ourselves).
            opener = urllib.request.OpenerDirector()
            opener.addheaders = [("User-Agent", "Capsule-Agent/1.0")]
            opener.add_handler(urllib.request.UnknownHandler())
            opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
            opener.add_handler(urllib.request.HTTPErrorProcessor())
            opener.add_handler(PinnedHTTPSHandler())
            return opener

        if KnownTools.NET_REQUEST not in capsule.allowed_tools:
            return {"ok": False, "tool": "net_request", "error": "tool not permitted by capsule"}

        url = arguments.get("url")
        if not isinstance(url, str):
            return {"ok": False, "tool": "net_request", "error": "'url' must be a string"}

        try:
            current_url = url
            hops = 0

            while True:
                parsed = urllib.parse.urlsplit(current_url)

                if parsed.scheme != "https":
                    return {"ok": False, "tool": "net_request", "error": "scheme must be https"}

                hostname = parsed.hostname
                if not hostname:
                    return {"ok": False, "tool": "net_request", "error": "missing hostname"}

                # Validate hostname (allowlist + private-IP check) and resolve to a pinned IP.
                try:
                    _validated_hostname, validated_ip = _validate_and_resolve(hostname)
                except PermissionError as exc:
                    return {"ok": False, "tool": "net_request", "error": str(exc)}
                except ValueError as exc:
                    # DNS failure or reserved IP — fail closed.
                    return {"ok": False, "tool": "net_request", "error": str(exc)}

                opener = _make_pinned_opener(hostname, validated_ip)
                req = urllib.request.Request(current_url, headers={"User-Agent": "Capsule-Agent/1.0"})

                try:
                    with opener.open(req, timeout=10) as response:
                        content = response.read().decode("utf-8", errors="replace")
                    return {
                        "ok": True,
                        "tool": "net_request",
                        "url": current_url,
                        "status": response.status,
                        "content": content,
                    }
                except urllib.error.HTTPError as exc:
                    status_code = exc.code
                    if status_code in (301, 302, 303, 307, 308):
                        location = exc.headers.get("Location")
                        if not location:
                            return {"ok": False, "tool": "net_request", "error": f"Redirect {status_code} with no Location header"}
                        hops += 1
                        if hops > _MAX_REDIRECTS:
                            return {"ok": False, "tool": "net_request", "error": f"Too many redirects (>{_MAX_REDIRECTS})"}
                        # Resolve relative redirect URLs against current URL.
                        current_url = urllib.parse.urljoin(current_url, location)
                        # Loop continues — re-validates the redirect target before connecting.
                        continue
                    return {"ok": False, "tool": "net_request", "error": f"HTTP {status_code}: {exc.reason}"}

        except Exception as exc:
            return {"ok": False, "tool": "net_request", "error": str(exc)}
