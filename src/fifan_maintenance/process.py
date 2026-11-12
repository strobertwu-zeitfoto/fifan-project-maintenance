"""Subprocess transport with limits while reading, not after communicate allocates."""
from __future__ import annotations

import subprocess
import threading
import os
import signal
import shutil
from pathlib import Path


def trusted_executable(name, root):
    """PATH selects installed tools, never material owned by the inspected tree."""
    candidate = shutil.which(name)
    if candidate is None:
        raise OSError('trusted executable unavailable: ' + name)
    executable = Path(candidate).resolve(strict=True)
    if executable.is_relative_to(Path(root).resolve(strict=True)):
        raise OSError('project-owned executable rejected: ' + name)
    return str(executable)


def run_bounded(command, *, input, timeout, env=None, cwd=None, output_limit=8 * 1024 * 1024):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    outputs = {"stdout": [], "stderr": []}
    overflow = threading.Event()

    def stop():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def read(stream, key, limit):
        size = 0
        try:
            while True:
                block = stream.read(65536)
                if not block:
                    break
                size += len(block)
                if size > limit:
                    overflow.set()
                    stop()
                    break
                outputs[key].append(block)
        finally:
            stream.close()

    def write():
        try:
            process.stdin.write(input)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass

    threads = [threading.Thread(target=write, daemon=True), threading.Thread(target=read, args=(process.stdout, "stdout", output_limit), daemon=True), threading.Thread(target=read, args=(process.stderr, "stderr", 65536), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop()
        process.wait()
        raise
    finally:
        for thread in threads:
            thread.join(timeout=1)
    if overflow.is_set():
        raise ValueError("subprocess output budget exhausted")
    return subprocess.CompletedProcess(command, process.returncode, b"".join(outputs["stdout"]), b"".join(outputs["stderr"]))
