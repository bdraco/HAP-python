"""Tests for the HAPServerProtocol."""
from socket import timeout
from unittest.mock import Mock, MagicMock, patch

import pytest

from pyhap import hap_protocol


def test_pair_e2e(driver):
    loop = MagicMock()
    transport = MagicMock()
    connections = {}

    hap_proto = hap_protocol.HAPServerProtocol(loop, connections, driver)
    hap_proto.connection_made(transport)
