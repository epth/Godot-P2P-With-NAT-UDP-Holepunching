#!/usr/bin/env python
"""UDP hole punching client."""
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

import sys

PORT = 5160

class ClientProtocol(DatagramProtocol):
    """
    Client protocol implementation.
    The clients registers with the rendezvous server.
    The rendezvous server returns connection details for the other peer.
    The client Initializes a connection with the other peer and sends a
    message.
    """

    def startProtocol(self):
        """Register with the rendezvous server."""
        self.server_connect = False
        self.peer_init = False
        self.peer_connect = False
        self.peer_address = None
        self.transport.write('{"this": False}'.encode(), ("35.197.160.85", PORT))

    def datagramReceived(self, datagram, host):
        pass
        # """Handle incoming datagram messages."""
        # if not self.server_connect:
        #     self.server_connect = True
        #     self.transport.write('ok', (sys.argv[1], int(sys.argv[2])))
        #     print 'Connected to server, waiting for peer...'

        # elif not self.peer_init:
        #     self.peer_init = True
        #     self.peer_address = self.toAddress(datagram)
        #     self.transport.write('init', self.peer_address)
        #     print 'Sent init to %s:%d' % self.peer_address

        # elif not self.peer_connect:
        #     self.peer_connect = True
        #     host = self.transport.getHost().host
        #     port = self.transport.getHost().port
        #     msg = 'Message from %s:%d' % (host, port)
        #     self.transport.write(msg, self.peer_address)

        # else:
        #     print 'Received:', datagram

if __name__ == '__main__':
    protocol = ClientProtocol()
    t = reactor.listenUDP(0, protocol)
    reactor.run()