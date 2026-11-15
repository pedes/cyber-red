"""Process runners.

* ``DockerRunner``: the default when Docker is usable. External tools run inside a pinned tool image with
  resource limits and no access to the host filesystem except the engagement workspace.
* ``NativeRunner``: opt-in fallback that runs binaries from the host ``PATH``.

Commands are always passed as an argv list (never through a shell). ``kill_all`` is the kill switch.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IMAGE = "cyberred/tools:latest"
MAX_CAPTURE = 4_000_000  # bytes kept per stream


@dataclass
class RunResult:
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool = False
    duration: float = 0.0


class Runner(ABC):
    name = "runner"

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)

    @abstractmethod
    def available(self, binary: str) -> bool: ...

    @abstractmethod
    async def run(self, argv: list[str], *, timeout: float, hosts: dict[str, str] | None = None) -> RunResult: ...

    @abstractmethod
    def kill_all(self) -> None: ...

    def map_path(self, p: Path) -> str:
        """Path of a workspace file as seen by the tool process."""
        return str(p)


async def _drain(stream: asyncio.StreamReader | None) -> bytes:
    if stream is None:
        return b""
    buf = bytearray()
    while chunk := await stream.read(65536):
        if len(buf) < MAX_CAPTURE:
            buf.extend(chunk[: MAX_CAPTURE - len(buf)])
    return bytes(buf)


class NativeRunner(Runner):
    name = "native"

    def __init__(self, workspace: Path) -> None:
        super().__init__(workspace)
        self._procs: set[asyncio.subprocess.Process] = set()

    def available(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    async def run(self, argv: list[str], *, timeout: float, hosts: dict[str, str] | None = None) -> RunResult:
        start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True, cwd=str(self.workspace),
        )
        self._procs.add(proc)
        timed_out = False
        try:
            out, err = await asyncio.wait_for(asyncio.gather(_drain(proc.stdout), _drain(proc.stderr)), timeout)
            await proc.wait()
        except asyncio.TimeoutError:
            timed_out = True
            self._kill(proc)
            out, err = b"", b""
            await proc.wait()
        except asyncio.CancelledError:
            self._kill(proc)
            raise
        finally:
            self._procs.discard(proc)
        return RunResult(out.decode(errors="replace"), err.decode(errors="replace"), proc.returncode, timed_out,
                         time.monotonic() - start)

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def kill_all(self) -> None:
        for p in list(self._procs):
            self._kill(p)


class DockerRunner(Runner):
    name = "docker"

    def __init__(self, workspace: Path, image: str = DEFAULT_IMAGE) -> None:
        super().__init__(workspace)
        self.image = image
        self._containers: set[str] = set()
        self._avail: dict[str, bool] = {}

    @staticmethod
    def usable(image: str = DEFAULT_IMAGE) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            if subprocess.run(["docker", "info"], capture_output=True, timeout=8).returncode != 0:
                return False
            return subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=8).returncode == 0
        except (subprocess.SubprocessError, OSError):
            return False

    def map_path(self, p: Path) -> str:
        try:
            return "/work/" + str(Path(p).resolve().relative_to(self.workspace.resolve()))
        except ValueError:
            return str(p)

    def available(self, binary: str) -> bool:
        if binary not in self._avail:
            try:
                r = subprocess.run(["docker", "run", "--rm", "--entrypoint", "which", self.image, binary],
                                   capture_output=True, timeout=30)
                self._avail[binary] = r.returncode == 0
            except (subprocess.SubprocessError, OSError):
                self._avail[binary] = False
        return self._avail[binary]

    async def run(self, argv: list[str], *, timeout: float, hosts: dict[str, str] | None = None) -> RunResult:
        name = f"cyberred-{uuid.uuid4().hex[:10]}"
        cmd = ["docker", "run", "--rm", "--name", name, "--cap-add", "NET_RAW", "--memory", "1g", "--pids-limit", "512",
               "--security-opt", "no-new-privileges", "-v", f"{self.workspace.resolve()}:/work", "-w", "/work"]
        for host, ip in (hosts or {}).items():
            cmd += ["--add-host", f"{host}:{ip}"]
        cmd += [self.image, *argv]
        self._containers.add(name)
        start = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        timed_out = False
        try:
            out, err = await asyncio.wait_for(asyncio.gather(_drain(proc.stdout), _drain(proc.stderr)), timeout)
            await proc.wait()
        except asyncio.TimeoutError:
            timed_out = True
            self._docker_kill(name)
            out, err = b"", b""
            await proc.wait()
        except asyncio.CancelledError:
            self._docker_kill(name)
            raise
        finally:
            self._containers.discard(name)
        return RunResult(out.decode(errors="replace"), err.decode(errors="replace"), proc.returncode, timed_out,
                         time.monotonic() - start)

    @staticmethod
    def _docker_kill(name: str) -> None:
        subprocess.run(["docker", "kill", name], capture_output=True)

    def kill_all(self) -> None:
        for n in list(self._containers):
            self._docker_kill(n)


def select_runner(kind: str, workspace: Path, image: str = DEFAULT_IMAGE) -> Runner:
    """kind: auto | docker | native."""
    if kind == "docker":
        if not DockerRunner.usable(image):
            raise RuntimeError(f"Docker is not usable or image '{image}' is missing (build it from docker/Dockerfile)")
        return DockerRunner(workspace, image)
    if kind == "native":
        return NativeRunner(workspace)
    return DockerRunner(workspace, image) if DockerRunner.usable(image) else NativeRunner(workspace)
