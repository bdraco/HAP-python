"""Tests for the HAPServerProtocol."""
from unittest.mock import MagicMock, Mock, patch
from cryptography.exceptions import InvalidTag

from pyhap import hap_protocol
from pyhap.accessory import Accessory


class MockHAPCrypto:
    """Mock HAPCrypto that only returns plaintext."""

    def __init__(self):
        """Create the mock object."""
        self._crypt_in_buffer = bytearray()  # Encrypted buffer

    def receive_data(self, buffer):
        """Receive data into the encrypted buffer."""
        self._crypt_in_buffer += buffer

    def decrypt(self):
        """Mock as plaintext."""
        decrypted = self._crypt_in_buffer
        self._crypt_in_buffer = bytearray()  # Encrypted buffer
        return decrypted

    def encrypt(self, data):
        """Mock as plaintext."""
        return data


def test_connection_management(driver):
    """Verify closing the connection removes it from the pool."""
    loop = MagicMock()
    addr_info = ("1.2.3.4", 5)
    transport = MagicMock(get_extra_info=Mock(return_value=addr_info))
    connections = {}

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)
    assert len(connections) == 1
    assert connections[addr_info] == hap_proto
    hap_proto.connection_lost(None)
    assert len(connections) == 0

    hap_proto.connection_made(transport)
    assert len(connections) == 1
    assert connections[addr_info] == hap_proto
    hap_proto.close()
    assert len(connections) == 0


def test_pair_setup(driver):
    """Verify an non-encrypt request."""
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)

    with patch.object(hap_proto.transport, "write") as writer:
        hap_proto.data_received(
            b"POST /pair-setup HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\nContent-Length: 6\r\nContent-Type: application/pairing+tlv8\r\n\r\n\x00\x01\x00\x06\x01\x01"  # pylint: disable=line-too-long
        )

    assert (
        writer.call_args_list[0][0][0].startswith(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/pairing+tlv8\r\n"
        )
        is True
    )


def test_get_accessories_without_crypto(driver):
    """Verify an non-encrypt request that expected to be encrypted."""
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)

    with patch.object(hap_proto.transport, "write") as writer:
        hap_proto.data_received(
            b"GET /accessories HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\n\r\n"  # pylint: disable=line-too-long
        )

    assert b'{"status": -70401}' in writer.call_args_list[0][0][0]


def test_get_accessories_with_crypto(driver):
    """Verify an encrypt request."""
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    driver.add_accessory(Accessory(driver, "TestAcc"))

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)

    hap_proto.hap_crypto = MockHAPCrypto()
    hap_proto.handler.is_encrypted = True

    with patch.object(hap_proto.transport, "write") as writer:
        hap_proto.data_received(
            b"GET /accessories HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\n\r\n"  # pylint: disable=line-too-long
        )

    assert b'"accessories"' in writer.call_args_list[0][0][0]


def test_crypto_failure_closes_connection(driver):
    """Verify a decrypt failure closes the connection."""
    loop = MagicMock()
    addr_info = ("1.2.3.4", 5)
    transport = MagicMock(get_extra_info=Mock(return_value=addr_info))
    connections = {}

    driver.add_accessory(Accessory(driver, "TestAcc"))

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)

    hap_proto.hap_crypto = MockHAPCrypto()
    hap_proto.handler.is_encrypted = True
    assert connections[addr_info] == hap_proto
    with patch.object(
        hap_proto.hap_crypto, "decrypt", side_effect=InvalidTag
    ), patch.object(hap_proto.transport, "write") as writer:
        hap_proto.data_received(b"any")  # pylint: disable=line-too-long

    assert len(connections) == 0
