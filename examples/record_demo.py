"""Re-record docs/demo.gif from the real CLI (not a mock-up).

    pip install -e .                       # so `agentshield` is on PATH
    python examples/record_demo.py         # writes demo.cast
    agg --theme monokai --font-size 15 --last-frame-duration 8 demo.cast docs/demo.gif

Runs `agentshield scan` on the demo PR inside a pseudo-terminal (so colours
and wrapping are exactly what a user sees), then writes an asciinema cast with
the command "typed" in. agg (github.com/asciinema/agg) turns the cast into a GIF.
"""

import fcntl
import json
import os
import pty
import shutil
import struct
import subprocess
import sys
import tempfile
import termios

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from demo import demo_diff  # noqa: E402

WIDTH = 100
COMMAND = "agentshield scan --diff ai-pr.diff"


def run_in_pty(cwd: str) -> str:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 60, WIDTH, 0, 0))
    proc = subprocess.Popen([shutil.which("agentshield"), "scan", "--diff", "ai-pr.diff", "--repo", "."],
                            cwd=cwd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    out = b""
    while True:
        try:
            chunk = os.read(master, 65536)
        except OSError:  # the program finished and closed the terminal
            break
        if not chunk:
            break
        out += chunk
    proc.wait()
    return out.decode()


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "ai-pr.diff"), "w") as fh:
            fh.write(demo_diff())
        text = run_in_pty(tmp)
    prompt = "\x1b[1;32m$\x1b[0m "
    t, events = 0.6, [[0.0, "o", prompt]]
    for ch in COMMAND:
        t += 0.045
        events.append([round(t, 3), "o", ch])
    t += 0.4
    events.append([round(t, 3), "o", "\r\n"])
    t += 1.2  # time for the registry lookups
    for line in text.splitlines(keepends=True):
        t += 0.06
        events.append([round(t, 3), "o", line])
    events.append([round(t + 0.3, 3), "o", prompt])
    with open("demo.cast", "w") as fh:
        fh.write(json.dumps({"version": 2, "width": WIDTH, "height": len(text.splitlines()) + 3}) + "\n")
        fh.writelines(json.dumps(e) + "\n" for e in events)
    print("wrote demo.cast")
    return 0


if __name__ == "__main__":
    sys.exit(main())
