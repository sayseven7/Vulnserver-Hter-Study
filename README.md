# VulnServer HTER Buffer Overflow Study

Work-in-progress repository for studying buffer overflow exploitation against VulnServer, focused on the `HTER` command.

## Status

This project is currently under development and is being used as a hands-on study environment for:

- fuzzing
- crash reproduction
- offset validation
- EIP control confirmation
- exploit development workflow

## Repository Contents

### `fuzzing.py`
Simple fuzzing script that sends increasing payload sizes to the `HTER` command in order to identify crash behavior and estimate the vulnerable input range.

### `xpl.py`
Initial proof-of-concept script used to validate payload structure and observe memory/register behavior during the crash.

## Current Environment

- Target: VulnServer
- Command under test: `HTER`
- Target host: `192.168.100.129`
- Target port: `9999`

## Notes

This repository is intended for educational purposes in a controlled lab environment.

The code is not final and may be updated as the study progresses.

## Author

Lucas Morais (SaySeven / @sayseven7)

## Disclaimer

For educational and authorized lab use only.