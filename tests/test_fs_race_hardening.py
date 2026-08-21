"""Filesystem race-condition and symlink/junction hardening tests.

Complements test_path_hardening.py (which only tests lexical pattern
matching against strings) with tests that touch a real filesystem: symlink
escapes, a Windows-junction escape, the TOCTOU window between authorization
and the actual filesystem operation, and the dir_fd-based secure-open helper
that closes it on platforms that support os.supports_dir_fd.

Several tests are skipped when the current platform/user cannot create
symlinks (unprivileged Windows) or does not support dir_fd (Windows
entirely). This is expected on the Windows development machine this project
is authored on -- run these under Linux/macOS/WSL, or inside the project's
own Docker image (python:3.11-slim), to exercise the POSIX-only coverage.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from app.config import Settings
from app.enforcement.tool_provider import _SECURE_OPEN_SUPPORTED, GovernedToolHandler
from app.governance.signer import Ed25519Signer
from app.models import KnownTools, PolicyDecision, SignedCapsule, TrustTier


@pytest.fixture
def workspace_tmp_path() -> Path:
    base = Path(".pytest_tmp") / "fs_race"
    path = base / str(uuid4())
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def runtime_settings(workspace_tmp_path: Path) -> Settings:
    return Settings(
        SIGNING_METHOD="ed25519",
        ED25519_PRIVATE_KEY_PATH=str(workspace_tmp_path / "ed25519.key"),
        DATABASE_PATH=str(workspace_tmp_path / "runtime.db"),
        CAPSULE_EXPIRY_HOURS=1,
    )


def policy_decision(
    *, tools: list[KnownTools], paths: list[str], tier: TrustTier = TrustTier.CONTRIBUTOR
) -> PolicyDecision:
    return PolicyDecision(
        allow=True,
        final_tools=tools,
        final_paths=paths,
        trust_tier=tier,
        require_human_approval=False,
        denial_reason=None,
        intent="fs race hardening test",
        source_hash="a" * 64,
        compiler_version="1.0.0",
    )


async def _sign(settings: Settings, tools: list[KnownTools], paths: list[str]) -> SignedCapsule:
    return await Ed25519Signer(settings=settings).sign(policy_decision(tools=tools, paths=paths))


def tools_call(name: str, arguments: dict, request_id: str | int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _try_symlink(link_path: Path, target: Path) -> bool:
    """Best-effort (re)create a symlink at link_path pointing to target.

    Returns False (never raises) if symlink creation is unsupported or
    unprivileged in the current environment, e.g. unprivileged Windows,
    which raises OSError [WinError 1314].
    """
    try:
        # Store an absolute target: a relative one is interpreted relative to
        # link_path's own directory, not the caller's, so it would silently
        # point at the wrong (nonexistent, still-in-workspace) location.
        target = target.resolve()
        if link_path.is_symlink():
            link_path.unlink()
        elif link_path.is_dir():
            # Path.unlink() raises IsADirectoryError on a real (non-symlink)
            # directory; must rmtree it, or this silently no-ops and every
            # caller misreports the failure as "not permitted in this
            # environment" instead of the real cause.
            shutil.rmtree(link_path)
        elif link_path.exists():
            link_path.unlink()
        link_path.symlink_to(target, target_is_directory=target.is_dir())
        return True
    except OSError:
        return False


@pytest.mark.skipif(sys.platform != "win32", reason="uses mklink /J, a Windows-specific mechanism")
def test_windows_junction_escape_is_denied(workspace_tmp_path: Path) -> None:
    """A directory junction pointing outside the workspace must be denied.

    Junctions do not require elevated privilege on Windows (unlike
    os.symlink) and, like symlinks, are transparently dereferenced by
    Path.resolve() -- so the existing lexical containment check in
    _resolve() must catch this even though no true symlink is involved.
    """
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.READ_FILE], ["allowed/**"]))

    outside_dir = workspace_tmp_path.parent / f"outside-{uuid4()}"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("top-secret", encoding="utf-8")
    junction = workspace_tmp_path / "allowed"

    try:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside_dir)],
            check=True,
            capture_output=True,
        )
        handler = GovernedToolHandler(workspace_tmp_path)

        result = handler(tools_call("read_file", {"path": "allowed/secret.txt"}), "c", capsule)

        assert result["ok"] is False
        assert "escapes" in result["error"]
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)


def test_read_file_denies_symlink_leaf_placed_before_authorization(
    workspace_tmp_path: Path,
) -> None:
    """A symlink already sitting at the target path must be denied.

    This mainly re-confirms _resolve()'s existing Path.resolve() dereference
    + containment check with a real symlink (docs/known-limitations.md
    previously described this as unhandled, which the source-grounded
    investigation found to be inaccurate for the static, pre-placed case).
    """
    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.READ_FILE], ["allowed/**"]))

    outside_secret = workspace_tmp_path.parent / f"secret-{uuid4()}.txt"
    outside_secret.write_text("top-secret", encoding="utf-8")
    try:
        allowed_dir = workspace_tmp_path / "allowed"
        allowed_dir.mkdir()
        link_path = allowed_dir / "file.txt"

        if not _try_symlink(link_path, outside_secret):
            pytest.skip("symlink creation is not permitted in this environment")

        handler = GovernedToolHandler(workspace_tmp_path)
        result = handler(tools_call("read_file", {"path": "allowed/file.txt"}), "c", capsule)

        assert result["ok"] is False
        assert "escapes" in result["error"]
    finally:
        outside_secret.unlink(missing_ok=True)


def test_read_file_toctou_swap_after_authorization_is_denied(workspace_tmp_path: Path) -> None:
    """Proves the TOCTOU fix: swap an authorized real file for a symlink
    AFTER _resolve() has already approved it, and confirm the read is still
    denied at actual-open time rather than silently following the symlink.
    """
    if not _SECURE_OPEN_SUPPORTED:
        pytest.skip(
            "dir_fd/O_NOFOLLOW secure-open requires os.supports_dir_fd "
            "(Linux/macOS); this platform falls back to best-effort pathlib I/O "
            "(see docs/known-limitations.md)"
        )

    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.READ_FILE], ["allowed/**"]))

    allowed_dir = workspace_tmp_path / "allowed"
    allowed_dir.mkdir()
    real_file = allowed_dir / "file.txt"
    real_file.write_text("original, safe content", encoding="utf-8")

    outside_secret = workspace_tmp_path.parent / f"secret-{uuid4()}.txt"
    outside_secret.write_text("top-secret", encoding="utf-8")

    handler = GovernedToolHandler(workspace_tmp_path)
    original_resolve = handler._resolve

    def resolve_then_swap(raw_path, capsule_arg):
        target = original_resolve(raw_path, capsule_arg)
        # Simulate an attacker winning the race the instant after
        # authorization: replace the just-authorized real file with a
        # symlink to a secret outside the workspace.
        if not _try_symlink(target, outside_secret):
            pytest.skip("symlink creation is not permitted in this environment")
        return target

    handler._resolve = resolve_then_swap
    try:
        result = handler(tools_call("read_file", {"path": "allowed/file.txt"}), "c", capsule)
    finally:
        outside_secret.unlink(missing_ok=True)

    assert result["ok"] is False
    assert "symlink" in result["error"]


def test_write_file_toctou_swap_after_authorization_is_denied(workspace_tmp_path: Path) -> None:
    """Write-side counterpart: an intermediate directory is swapped for a
    symlink after authorization but before the write actually occurs."""
    if not _SECURE_OPEN_SUPPORTED:
        pytest.skip(
            "dir_fd/O_NOFOLLOW secure-open requires os.supports_dir_fd "
            "(Linux/macOS); this platform falls back to best-effort pathlib I/O "
            "(see docs/known-limitations.md)"
        )

    settings = runtime_settings(workspace_tmp_path)
    capsule = asyncio.run(_sign(settings, [KnownTools.WRITE_FILE], ["allowed/**"]))

    allowed_dir = workspace_tmp_path / "allowed"
    allowed_dir.mkdir()

    outside_dir = workspace_tmp_path.parent / f"outside-{uuid4()}"
    outside_dir.mkdir()

    handler = GovernedToolHandler(workspace_tmp_path)
    original_resolve = handler._resolve

    def resolve_then_swap(raw_path, capsule_arg):
        target = original_resolve(raw_path, capsule_arg)
        # Swap the *parent directory* for a symlink after authorization but
        # before the write executes.
        if not _try_symlink(allowed_dir, outside_dir):
            pytest.skip("symlink creation is not permitted in this environment")
        return target

    handler._resolve = resolve_then_swap
    try:
        result = handler(
            tools_call("write_file", {"path": "allowed/new.txt", "content": "attacker payload"}),
            "c",
            capsule,
        )
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)

    assert result["ok"] is False
    assert "symlink" in result["error"]
    assert not (outside_dir / "new.txt").exists()


def test_secure_open_denies_symlinked_intermediate_directory(workspace_tmp_path: Path) -> None:
    """Direct unit test: a symlinked intermediate directory component (not
    just the leaf) must be rejected by the secure-open helper."""
    if not _SECURE_OPEN_SUPPORTED:
        pytest.skip("dir_fd/O_NOFOLLOW secure-open requires os.supports_dir_fd (Linux/macOS)")

    outside_dir = workspace_tmp_path.parent / f"outside-{uuid4()}"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("top-secret", encoding="utf-8")

    link_dir = workspace_tmp_path / "linked"
    try:
        if not _try_symlink(link_dir, outside_dir):
            pytest.skip("symlink creation is not permitted in this environment")

        handler = GovernedToolHandler(workspace_tmp_path)
        with pytest.raises(PermissionError, match="symlink"):
            handler._secure_open_fd(["linked", "secret.txt"], for_write=False)
    finally:
        shutil.rmtree(outside_dir, ignore_errors=True)


def test_secure_open_creates_missing_intermediate_directories(workspace_tmp_path: Path) -> None:
    """Direct unit test: legitimate nested-directory writes still work
    through the secure-open helper (mkdir-on-demand tolerance)."""
    if not _SECURE_OPEN_SUPPORTED:
        pytest.skip("dir_fd/O_NOFOLLOW secure-open requires os.supports_dir_fd (Linux/macOS)")

    handler = GovernedToolHandler(workspace_tmp_path)
    fd = handler._secure_open_fd(["a", "b", "c", "new.txt"], for_write=True)

    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("nested content")

    assert (workspace_tmp_path / "a" / "b" / "c" / "new.txt").read_text(encoding="utf-8") == (
        "nested content"
    )
