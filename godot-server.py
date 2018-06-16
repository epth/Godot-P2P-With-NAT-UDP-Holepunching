#!/usr/bin/env python
#based on: https://github.com/stylesuxx/udp-hole-punching
#great info here: http://www.brynosaurus.com/pub/net/p2pnat/
"""
    Handshake server for UDP hole-punching.
    Firewall must allow ingress and egress at SERVER_PORT = 5160
    Peers can send two kinds of messages:
        {
            'type': 'registering-server',
            'sender': <unique string>,
            'local-address': [ip, port],
        }
    registers a server peer under the name user-name, and
        {
            'type': 'request-to-join-server',
            'sender': <unique string>,
            'local-address': [ip, port],
            'server-name': <unique string>
        }
    initiates a linking between the sender and the server peer registered user server-name.

    This intermediary server does this by sending each of the two peers the other peer's 
    private and public (garnered form the incoming message headers themselves) addresses.
    From there, it's up to the peers to hole-punch and link to each other.

    note: currently does not support server list refresh and doesn't even think about packet unreliability.

"""
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet import task
import json
import sys

SERVER_PORT = 5160

class ServerProtocol(DatagramProtocol):
    def __init__(self):
        """Initialize with empy server list."""
        self.serverHosts = {}

    def validateData(self, jData):
        """
        Checks whether all required keys are present.
        Handshake server should atach 'global-address'
        Returns json if good, None otherwise
        """
        ret = {}
        #required for all peers
        requiredKeys = ['type', 'global-address']
        for key in requiredKeys:
            if key in jData:
                ret[key] = jData[key]
            else:
                message = "missing info from packet data: " + key
                self.sendError(jData, message)
                return
        #required depending on type
        if jData['type'] == 'requesting-to-join-server':
            requiredKeys = ['server-name', 'local-address', 'sender']
        elif jData['type'] == 'registering-server':
            requiredKeys = ['seconds-before-expiry', 'local-address', 'sender']
        else:
            requiredKeys = []
        for key in requiredKeys:
            if key in jData:
                ret[key] = jData[key]
            else:
                message = "missing info from packet data: " + key
                self.sendError(jData, message)
                return
        return ret    



    def makeHandshakeJson(self, jData):
        """forms data into that which we want to send back"""
        ret = {}
        ret['type'] = 'providing-peer-handshake-info'
        ret['peer-name'] = jData['sender']
        ret['global-address'] = jData['global-address']
        ret['local-address'] = jData['local-address']
        return ret

    def sendError(self, jData, message):
        """sends a packet of type server-error"""
        data = {
                'type': 'server-error',
                'intended-recipient': jData['sender'],
                'message': message
            }
        self.transport.write(json.dumps(data).encode(), jData['global-address'])




    def datagramReceived(self, datagram, address):
        """
        Handles incoming packets.
        """
        #binary -> string -> json dict
        data = json.loads(datagram.decode('utf-8'))
        print("received " + str(data) + " from " + address[0])

        data['global-address'] = (address[0], address[1])
        #gather the user info
        jData = self.validateData(data)
        if jData == None:
            print("ill-formed datagram")
            return
        
        #send back a list of servers if that's what we're doing
        if jData['type'] == 'requesting-server-list':
            data = {
                'type': 'providing-server-list',
                'intended-recipient': jData['sender'],
                'server-list' : self.serverHosts.keys()
            }
            self.transport.write(json.dumps(data).encode(), address)
            print("sent server list")

        #register server if that's what we're doing
        if jData['type'] == 'registering-server':
            #reject if a server exists with different address
            if jData['sender'] in self.serverHosts:
                existingAddress =  self.serverHosts[jData['sender']]['global-address']
                if jData['global-address'] != existingAddress:
                    self.sendError(jData, "server already exists")
                    return
            #store the server by its sender
            self.serverHosts[jData['sender']] = jData
            print(jData['sender'] + " added to server list")
            #send back confirmation
            data = {
                'type': 'confirming-registration',
                'intended-recipient': jData['sender']
            }
            self.transport.write(json.dumps(data).encode(), address)
            print("sent confirmation")

        #otherwise, we're linking a server and a nonserver peer
        elif jData['type'] == 'requesting-to-join-server':
            #check server exists
            print("joining " + jData['sender'] + " and " + jData['server-name'])
            if not jData['server-name'] in self.serverHosts.keys():
                message = jData['server-name'] + " not found"
                print(message)
                self.sendError(jData, message)
                return
            #make handshake messages
            serverJData = self.serverHosts[jData['server-name']]
            serverInfo = self.makeHandshakeJson(serverJData)
            clientInfo = self.makeHandshakeJson(jData)
            serverInfo['intended-recipient'] = clientInfo['peer-name']
            clientInfo['intended-recipient'] = serverInfo['peer-name']
            #send them out
            #beware that tuples become lists in json- peers will need to change them back to tuples
            self.transport.write(json.dumps(serverInfo).encode(), clientInfo['global-address'])
            self.transport.write(json.dumps(clientInfo).encode(), serverInfo['global-address'])
            print("sent linking info to " + jData['server-name'] + " and " + jData['sender'])

    def serverHostRefresh(self):
        serversToRemove = []
        for serverName, serverInfo in self.serverHosts.items():
            serverInfo['seconds-before-expiry'] -= 1
            if serverInfo['seconds-before-expiry'] <= 0:
                serversToRemove.append(serverName)
        for serverToRemove in serversToRemove:
            self.serverHosts.pop(serverToRemove)
        print("-> " + str(self.serverHosts))

if __name__ == '__main__':
    listener = ServerProtocol()
    reactor.listenUDP(SERVER_PORT, listener)
    task.LoopingCall(listener.serverHostRefresh).start(1.0)
    reactor.run()


"""
todo 
: make it refresh server list 
: send back confirmation / error message
"""