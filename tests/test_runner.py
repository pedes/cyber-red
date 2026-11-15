import asyncio
import sys
import time

from conftest import run_async
from cyberred.sandbox import NativeRunner, select_runner


def test_native_runner_captures_output_and_exit_code(tmp_path):
    r = NativeRunner(tmp_path)
    res = run_async(r.run([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"], timeout=10))
    assert (res.stdout.strip(), res.stderr.strip(), res.exit_code, res.timed_out) == ("out", "err", 3, False)


def test_native_runner_timeout_kills_the_whole_process_group(tmp_path):
    r = NativeRunner(tmp_path)
    marker = tmp_path / "child-survived"
    # parent spawns a child that would create a marker after 2s; both must die on timeout
    code = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time,pathlib; time.sleep(2); pathlib.Path(r\"{marker}\").write_text(\"x\")']); time.sleep(30)"
    t0 = time.monotonic()
    res = run_async(r.run([sys.executable, "-c", code], timeout=0.5))
    assert res.timed_out and time.monotonic() - t0 < 5
    time.sleep(2.5)
    assert not marker.exists()


def test_kill_all_stops_running_processes(tmp_path):
    r = NativeRunner(tmp_path)

    async def go():
        task = asyncio.create_task(r.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=60))
        await asyncio.sleep(0.5)
        r.kill_all()
        return await asyncio.wait_for(task, 5)

    res = run_async(go())
    assert res.exit_code != 0 and not res.timed_out


def test_no_shell_interpretation_of_arguments(tmp_path):
    r = NativeRunner(tmp_path)
    res = run_async(r.run([sys.executable, "-c", "import sys; print(sys.argv[1])", "$(whoami); echo pwned"], timeout=10))
    assert res.stdout.strip() == "$(whoami); echo pwned"


def test_availability_and_runner_selection(tmp_path):
    assert NativeRunner(tmp_path).available("python3") or NativeRunner(tmp_path).available("sh")
    assert not NativeRunner(tmp_path).available("definitely-not-a-binary-xyz")
    assert select_runner("native", tmp_path).name == "native"
