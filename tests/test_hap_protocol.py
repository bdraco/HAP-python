"""Tests for the HAPServerProtocol."""
import logging
from unittest.mock import MagicMock, Mock, patch

import pytest

from pyhap import hap_protocol


def test_connection_management(driver):
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


def test_pair_setup(driver):
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)

    with patch.object(hap_proto, "write") as writer:
        hap_proto.data_received(
            b"POST /pair-setup HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\nContent-Length: 6\r\nContent-Type: application/pairing+tlv8\r\n\r\n\x00\x01\x00\x06\x01\x01"  # pylint: disable=line-too-long
        )

    assert writer.call_args_list[0].startswith(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/pairing+tlv8\r\n"
    )


@pytest.mark.skip
def test_encrypted_get_accessories(driver):
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    logging.basicConfig(level=logging.DEBUG, format="[%(module)s] %(message)s")

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)
    hap_proto.shared_key = b"l\xbfQ\x82\xabp\xb1\xeft\xa5\xcb\xcb\xaa(i\n\x9a\x83\x11\xeb\x8e\x11{\xf5}\xdf\xff\xebP\xfd\xa3("  # pylint: disable=line-too-long
    hap_proto._set_ciphers()  # pylint: disable=protected-access

    raw_request = hap_proto._encrypt_data(  # pylint: disable=protected-access
        b"GET /accessories HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\n\r\n"
    )

    with patch.object(hap_proto, "write") as writer:
        hap_proto.data_received(raw_request)

    assert writer.call_args_list[0].startswith(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/pairing+tlv8\r\n"
    )
