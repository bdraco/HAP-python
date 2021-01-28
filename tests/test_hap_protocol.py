"""Tests for the HAPServerProtocol."""
from socket import timeout
from unittest.mock import Mock, MagicMock, patch

import pytest
import logging
from pyhap import hap_protocol


def test_pair_setup(driver):
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)

    with patch.object(hap_proto, "write") as writer:
        hap_proto.data_received(
            b"POST /pair-setup HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\nContent-Length: 6\r\nContent-Type: application/pairing+tlv8\r\n\r\n\x00\x01\x00\x06\x01\x01"
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
    hap_proto.shared_key = b"l\xbfQ\x82\xabp\xb1\xeft\xa5\xcb\xcb\xaa(i\n\x9a\x83\x11\xeb\x8e\x11{\xf5}\xdf\xff\xebP\xfd\xa3("
    hap_proto._set_ciphers()

    raw_request = hap_proto._encrypt_data(
        b"GET /accessories HTTP/1.1\r\nHost: Bridge\\032C77C47._hap._tcp.local\r\n\r\n"
    )

    with patch.object(hap_proto, "write") as writer:
        hap_proto.data_received(raw_request)

    assert writer.call_args_list[0].startswith(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/pairing+tlv8\r\n"
    )
