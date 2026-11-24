# Contributing

Create an issue describing the problem or proposed behavior before a large change. Include the OS, version and minimal reproduction for bugs. Keep examples free of real device data and credentials.

Install `requirements.txt` in a Python virtual environment, make a focused change, and run the unit suite and zero-probe self-check described in the README. Tests must use mocked discovery or owned loopback endpoints. Do not scan a CI runner's subnet.

Keep evidence semantics accurate: cached neighbors are distinct from direct responses, unknown data stays unknown, and untested ports must not be reported as checked. Preserve cancellation, private-scope limits, retention and export safety. Update documentation when behavior changes.

Application contributions use the existing MIT license. Retain third-party notices. Windows package changes require native acceptance testing before claiming Windows verification.
