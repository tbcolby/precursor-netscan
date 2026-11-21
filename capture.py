"""Renode capture sequence for Net Check.

Run from xous-dev-toolkit:
    python3 scripts/renode_capture.py --app netscan --script ../precursor-netscan/capture.py

Contract: run(ctl, outdir) -> number of failed steps. The app is already launched.
Only the offline screens are captured (subnet calculator, port reference, and the
confirmation screen); it never presses Enter on the confirmation, so no connection
is attempted. Not yet run.
"""
import os


def run(ctl, outdir) -> int:
    failures = 0

    def shot(name):
        nonlocal failures
        if not ctl.try_screenshot(os.path.join(outdir, name)):
            failures += 1

    shot("01_home.png")
    ctl.timed_key("Down", after=1.0)
    ctl.timed_key("Right", after=1.0)  # subnet calculator
    ctl.inject_line("192.168.1.77/24")  # types the text and presses Enter
    ctl.sleep(1.0)
    shot("02_subnet.png")
    ctl.timed_key("BackSpace", after=1.0)  # back to the input
    ctl.timed_key("F4", after=1.0)  # home
    ctl.timed_key("Down", after=1.0)
    ctl.timed_key("Right", after=1.0)  # port reference
    shot("03_ports.png")
    ctl.timed_key("F4", after=1.0)  # home
    ctl.timed_key("Up", after=1.0)
    ctl.timed_key("Up", after=1.0)
    ctl.timed_key("Right", after=1.0)  # host input
    ctl.inject_line("192.168.1.10")
    ctl.sleep(1.0)
    ctl.inject_line("22,80")
    ctl.sleep(1.0)
    shot("04_confirm.png")  # stop here: do not confirm
    ctl.timed_key("F4", after=1.0)
    return failures
