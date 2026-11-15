import asyncio
from pathlib import Path

import pytest

from cyberred.config import Config
from cyberred.core import Engagement
from cyberred.core.executor import ApprovalRequest
from cyberred.sandbox import Runner, RunResult


class FakeRunner(Runner):
    """Pretends external binaries exist and returns scripted stdout."""

    name = "fake"

    def __init__(self, workspace: Path, binaries=(), outputs=None):
        super().__init__(workspace)
        self.binaries = set(binaries)
        self.outputs = outputs or {}
        self.calls: list[list[str]] = []
        self.killed = False

    def available(self, binary):
        return binary in self.binaries

    async def run(self, argv, *, timeout, hosts=None):
        self.calls.append(list(argv))
        out = self.outputs.get(argv[0], "")
        return RunResult(out(argv) if callable(out) else out, "", 0, False, 0.01)

    def kill_all(self):
        self.killed = True


def run_async(coro):
    return asyncio.run(coro)


async def approve_all(req: ApprovalRequest) -> str:
    return "yes"


async def approve_always(req: ApprovalRequest) -> str:
    return "always"


@pytest.fixture
def make_eng(tmp_path):
    made = []

    def _mk(include=("127.0.0.1",), mode="lab", exclude=(), binaries=(), outputs=None, approver=None, hint=False, **cfg_extra):
        data = {"engagement": {"name": "t", "mode": mode, "authorization": "SOW-1"},
                "scope": {"include": list(include), "exclude": list(exclude)}}
        data.update(cfg_extra)
        cfg = Config.model_validate(data)
        ws = tmp_path / f"ws{len(made)}"
        runner = FakeRunner(ws, binaries, outputs)
        kw = {"approver": approver} if approver else {}
        eng = Engagement(cfg, ws, runner=runner, hint=hint, verbose=False, **kw)
        made.append(eng)
        return eng

    yield _mk
    for e in made:
        e.close()
