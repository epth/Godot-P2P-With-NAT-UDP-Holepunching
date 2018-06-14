#!/usr/bin/env python
#based on: https://github.com/stylesuxx/udp-hole-punching
#great info here: http://www.brynosaurus.com/pub/net/p2pnat/
"""

UDP hole punching peer. Does not require port forwarding
note: does not consider packet unreliability or ordering!
note: myPrivateIp can be found using ipconfig or similar

there are six phases to this peer:
    1) send initial message to handshake server either registering as server or
        seeking to join currently registered peer
    2) If you're a server, wait until someone asks the handshake server to join with you
    3) using info received from server, send differentiated packets to private and public address of other peer
    4) Mirror whatever packet made it through from other peer's step 3 back to them
    5) Receive mirrored packet, which tells us which address (public or private) to use. 
    6) Communicate with peer freely


"""
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import sys
import json

#public address info for intermediary server
HANDSHAKE_SERVER_IP = '35.197.160.85'
HANDSHAKE_SERVER_PORT = 5160


myPrivateIp = '192.168.1.127'
myPrivatePort = None
userName = "" #set by cli
iAmServer = False #set by cli
serverName = "" #set by cli
serverPassword = "" #set by cli

class ClientProtocol(DatagramProtocol):

    def startProtocol(self):
        """Either register as server, or initiate peer connection"""
        #init state trackers
        self.initialMessageSentToServer = False
        self.sentPacketToPeerPublicAndPrivateAddresses = False
        self.mirroredBackWhicheverPacketMadeIt = False
        self.peerConnectionEstablished = False
        #init peer info
        self.peerPublicAddress = None
        self.peerPrivateAddress = None
        self.peerAddress = None 
        self.peerUserName = None

        #talk to handshake server
        if iAmServer:
            data = {
                'registering-server': True,
                'user-name': userName,
                'private-ip': myPrivateIp,  
                'private-port': myPrivatePort
            }
        else:
            data = {
                'registering-server': False,
                'user-name': userName,
                'private-ip': myPrivateIp,  
                'private-port': myPrivatePort,
                'server-name' : serverName,
                'server-password': serverPassword,
            }
        self.transport.write(json.dumps(data).encode(), (HANDSHAKE_SERVER_IP, HANDSHAKE_SERVER_PORT))
        print("sent initial message to server " + HANDSHAKE_SERVER_IP + ":" + str(HANDSHAKE_SERVER_PORT))
        self.initialMessageSentToServer = True




    def datagramReceived(self, datagram, host):

        if not self.sentPacketToPeerPublicAndPrivateAddresses:
            #this message was info about peer from handshake server
            #we want to send a packet to the peer's public and private
            #addresses, so we can see which one to use going forward
            peerInfo = json.loads(datagram)
            print("peer info received: " + str(peerInfo))
            #json converts tuples to list- we need to convert them back to tuples
            self.peerPublicAddress = tuple(peerInfo['public-address'])
            self.peerPrivateAddress = tuple(peerInfo['private-address'])
            self.peerUserName = peerInfo['user-name']

            #send a different message to the public and private addresses
            #they're just going to be mirrored back, so we can tell which one made it
            dataForPublicAddressAttempt = {
                "user-name" : userName,
                "used-public": True
            }
            dataForPrivateAddressAttempt = {
                "user-name" : userName,
                "used-public": False
            }
            self.transport.write(json.dumps(dataForPublicAddressAttempt).encode(), self.peerPublicAddress)
            print("sent packet to peer's public address: " + str(self.peerPublicAddress))
            self.transport.write(json.dumps(dataForPrivateAddressAttempt).encode(), self.peerPrivateAddress)
            print("sent packet to peer's private address: " + str(self.peerPrivateAddress))
            self.sentPacketToPeerPublicAndPrivateAddresses = True


        elif not self.mirroredBackWhicheverPacketMadeIt:
            #we just mirror back the packet so the other peer knows which one made it
            #we have to send it back to both because we still don't know which one
            #made it to THEM
            self.transport.write(datagram, self.peerPublicAddress)
            self.transport.write(datagram, self.peerPrivateAddress)
            print("mirrored back: " + str(json.loads(datagram)))
            self.mirroredBackWhicheverPacketMadeIt = True


        elif not self.peerConnectionEstablished:
            #this packet will be one of the packets we sent
            dataFromAttempt = json.loads(datagram)
            if dataFromAttempt['used-public']:
                self.peerAddress = self.peerPublicAddress
            else:
                self.peerAddress = self.peerPrivateAddress
            print('peer address set as: ' + str(self.peerAddress))
            #send a friendly message
            message = {
                "type": "message",
                "user-name": userName,
                "body": "hello you!"
            }
            self.transport.write(json.dumps(message).encode(), self.peerAddress)
            self.peerConnectionEstablished = True


        else:
            #We just received a normal message
            jData = json.loads(datagram)
            print("received from: " + jData['user-name'])
            print(jData['body'])


if __name__ == '__main__':
    usage = "for servers: \n python peer.py server <server-name>\n\nfor others: \n python peer.py host <user-name> <server-name>"
    #set up either client or server from command line arguments
    #the ports chosen are almost arbitrary, but must be different if on the same computer
    if len(sys.argv) < 3:
        print(usage)
        exit(-1)
    userName = sys.argv[2]

    #server init
    if sys.argv[1] == 'server':
        iAmServer = True
        myPrivatePort = 3335
        print("running as server on port " + str(myPrivatePort))
    #client init
    elif sys.argv[1] == 'host':
        if len(sys.argv) < 4:
            print(usage)
            exit(-1)
        iAmServer = False
        myPrivatePort = 3334
        print("running as host on port " + str(myPrivatePort))
        serverName = sys.argv[3]
        #optional password
        if len(sys.argv) > 4:
            serverPassword = sys.argv[4]

    reactor.listenUDP(myPrivatePort, ClientProtocol())
    reactor.run()

    # protocol = ClientProtocol()
    # t = reactor.listenUDP(myPrivatePort, protocol)
    # reactor.run()