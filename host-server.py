#!/usr/bin/env python
"""UDP hole punching client."""
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

import sys
import json

HANDSHAKE_SERVER_IP = '35.197.160.85'
HANDSHAKE_SERVER_PORT = 5160


MY_PRIVATE_IP = '192.168.1.127'
myPort = None
userName = "" #set by cli
isServer = False #set by cli
serverName = "" #set by cli
serverPassword = "" #set by cli

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
        self.peer_holepunched = False
        self.peer_mirrored = False
        self.peer_connect = False
  
        if (isServer):
            data = {
                'registering-server': True,
                'user-name': userName,
                'private-ip': MY_PRIVATE_IP,  
                'private-port': myPort
            }
        else:
            data = {
                'registering-server': False,
                'user-name': userName,
                'private-ip': MY_PRIVATE_IP,  
                'private-port': myPort,
                'server-name' : serverName,
                'server-password': serverPassword,
            }

        self.transport.write(json.dumps(data).encode(), (HANDSHAKE_SERVER_IP, HANDSHAKE_SERVER_PORT))
        print("sent")

    def datagramReceived(self, datagram, host):
        print("received info")

        if not self.peer_holepunched:
            self.peer_init = True
            self.peerInfo = json.loads(datagram)
            print(self.peerInfo)
            self.peerPublicAddress = self.peerInfo['public-address']
            self.peerPrivateAddress = self.peerInfo['private-address']
            self.peerUserName = self.peerInfo['user-name']
            dataForPublicAttempt = {
                "user-name" : userName,
                "used-public": True
            }
            self.transport.write(json.dumps(dataForPublicAttempt).encode(), self.peerPublicAddress)
            dataForPrivateAttempt = {
                "user-name" : userName,
                "used-public": False
            }
            self.transport.write(json.dumps(dataForPrivateAttempt).encode(), self.peerPublicAddress)
            print("sent to peer's public and private addresses")

        elif not self.peer_mirrored:
            self.transport.write(datagram, self.peerPublicAddress)
            self.peer_mirrored = True
            print("mirrored back: " + str(json.loads(datagram))

        elif not self.peer_connect:
            j = json.loads(datagram)
            if j['used-public']:
                self.peerAddress = self.peerPublicAddress
            else:
                self.peerAddress = self.peerPrivateAddress
            print('peer address set as: ' + peerAddress)
            self.transport.write(json.dumps({"HELLO!": "YOU!"}).encode(), self.peerAddress)
        else:
            print("received: " + str(json.loads(datagram))

if __name__ == '__main__':
    if sys.argv[1] == 'server':
        isServer = True
        myPort = 3335
        print("running as server")
    elif sys.argv[1] == 'host':
        isServer = False
        myPort = 3334
        print("running as host")
        serverName = sys.argv[3]
        if len(sys.argv) > 4:
            serverPassword = sys.argv[4]
    userName = sys.argv[2]


    protocol = ClientProtocol()
    t = reactor.listenUDP(0, protocol)
    reactor.run()