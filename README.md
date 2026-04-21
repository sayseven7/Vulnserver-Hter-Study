# VulnServer HTER Buffer Overflow Study

Structured lab repository for studying stack-based buffer overflow techniques against VulnServer, with focus on the HTER workflow and exploit development lifecycle.

## Project Goal

This repository is designed to support practical, step-by-step training in a controlled security environment.

Main objectives:

- perform protocol fuzzing and crash discovery
- reproduce and analyze crashes
- validate offset and EIP control
- identify bad characters
- evolve from proof-of-concept to exploit script

## VulnServer Download

To test these scripts, download VulnServer from the official GitHub repository:

- https://github.com/stephenbradshaw/vulnserver

Run VulnServer only in an isolated and authorized lab environment.

## Repository Structure

- bad.py: helper script for bad character generation and checks
- fuzzing.py: sends incremental payload sizes to map vulnerable input ranges
- outro.py: payload pattern and offset-oriented helper flow
- xpl.py: exploit-oriented script with payload construction and target communication

## Lab Setup

Recommended environment:

- attacker machine: Linux with Python 3
- target machine: Windows running VulnServer
- debugger: Immunity Debugger (or equivalent) on target machine
- isolated network segment between attacker and target

## Quick Start

1. Start VulnServer on the target machine.
2. Confirm IP and port configuration in xpl.py.
3. Run your selected script from this repository.
4. Observe server and debugger behavior for crash analysis and exploit iteration.

## Example Execution

Run exploit script:

python3 xpl.py

Run fuzzing script:

python3 fuzzing.py

## Scope and Safety

This project is for education and authorized security testing only.

Do not run these techniques on systems without explicit permission.

## Author

Lucas Morais (SaySeven / @sayseven7)
