"""This module implements the communication of HAP.

The HAPServerProtocol is a protocol implementation that manages the "TLS" of the connection.
"""
import asyncio
import logging

import h11

from .hap_crypto import HAPCrypto
from .hap_handler import HAPResponse, HAPServerHandler
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)


class HAPServerProtocol(asyncio.Protocol):
    """A asyncio.Protocol implementing the HAP protocol."""

    def __init__(self, loop, connections, accessory_handler) -> None:
        self.loop = loop
        self.conn = h11.Connection(h11.SERVER)
        self.connections = connections
        self.accessory_handler = accessory_handler
        self._handler = None
        self.peername = None
        self.transport = None

        self.request = None
        self.request_body = None
        self.response = None

        self.hap_crypto = None

    def connection_lost(self, exc: Exception) -> None:
        """Handle connection lost."""
        logger.debug("%s: Connection lost: %s", self.peername, exc)
        self.close()

    def connection_made(self, transport: asyncio.Transport) -> None:
        """Handle incoming connection."""
        peername = transport.get_extra_info("peername")
        logger.info("%s: Connection made", peername)
        self.transport = transport
        self.peername = peername
        self.connections[peername] = self
        self._handler = HAPServerHandler(self.accessory_handler, peername)

    def write(self, data: bytes) -> None:
        """Write data to the client."""
        if self.hap_crypto:
            result = self.hap_crypto.encrypt(data)
            logger.debug("%s: Send encrypted: %s", self.peername, data)
            self.transport.write(result)
        else:
            logger.debug("%s: Send unencrypted: %s", self.peername, data)
            self.transport.write(data)

    def close(self) -> None:
        """Remove the connection and close the transport."""
        if self.peername in self.connections:
            del self.connections[self.peername]
        self.transport.close()

    def send_response(self, response: HAPResponse) -> None:
        """Send a HAPResponse object."""
        self.write(
            self.conn.send(
                h11.Response(
                    status_code=response.status_code,
                    reason=response.reason,
                    headers=response.headers,
                )
            )
            + self.conn.send(h11.Data(data=response.body))
            + self.conn.send(h11.EndOfMessage())
        )

    def data_received(self, data: bytes) -> None:
        """Process new data from the socket."""
        if self.hap_crypto:
            self.hap_crypto.receive_data(data)
            try:
                unencrypted_data = self.hap_crypto.decrypt()
            except InvalidTag as ex:
                logger.debug(
                    "%s: Decrypt failed, closing connection: %s", self.peername, ex
                )
                self.close()
                return
            if unencrypted_data == b"":
                logger.debug("No decryptable data")
                return
            logger.debug("%s: Recv decrypted: %s", self.peername, unencrypted_data)
            self.conn.receive_data(unencrypted_data)
        else:
            self.conn.receive_data(data)
            logger.debug("%s: Recv unencrypted: %s", self.peername, data)

        while self._process_one_event():
            pass

    def _process_one_event(self) -> bool:
        """Process one http event."""
        event = self.conn.next_event()

        logger.debug("%s: h11 Event: %s", self.peername, event)

        if self.conn.our_state is h11.MUST_CLOSE:
            return self._handle_invalid_conn_state("connection state is must close")

        if event is h11.NEED_DATA:
            return False

        if event is h11.PAUSED:
            if self.request:
                return self._handle_invalid_conn_state(
                    "paused when a request is in progress"
                )
            self.conn.start_next_cycle()
            return True

        if isinstance(event, h11.Request):
            self.request = event
            self.request_body = b""
            return True

        if isinstance(event, h11.Data):
            self.request_body += event.data
            return True

        if isinstance(event, h11.EndOfMessage):
            response = self._handler.dispatch(self.request, bytes(self.request_body))
            self._process_response(response)
            self.request = None
            self.request_body = None
            return True

        return self._handle_invalid_conn_state("Unexpected event: {}".format(event))

    def _process_response(self, response) -> None:
        """Process a response from the handler."""
        if response.task:
            # If there is a task pending we will schedule
            # the response later
            self.response = response
            response.task.add_done_callback(self._handle_response_ready)
        else:
            self.send_response(response)

        # If we get a shared key, upgrade to encrypted
        if response.shared_key:
            self.hap_crypto = HAPCrypto(response.shared_key)

    def _handle_response_ready(self, task: asyncio.Task) -> None:
        """Handle delayed response."""
        response = self.response
        self.response = None
        response.body = task.result()
        self.send_response(response)

    def _handle_invalid_conn_state(self, message):
        """Log invalid state and close."""
        logger.debug(
            "%s: Invalid state: %s: close the client socket",
            message,
            self.peername,
        )
        self.close()
        return False
