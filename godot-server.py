#!/usr/bin/env python
#based on: https://github.com/stylesuxx/udp-hole-punching
#great info here: http://www.brynosaurus.com/pub/net/p2pnat/
"""
    Handshake server for UDP hole-punching.
    Firewall must allow ingress and egress at SERVER_PORT = 5160
    Peers can send two kinds of messages:
        {
            'type': 'registering-server',
            'user-name': <unique string>,
            'local-ip': <string>,
            'local-port' <int>
        }
    registers a server peer under the name user-name, and
        {
            'type': 'request-to-join-server',
            'user-name': <unique string>,
            'local-ip': <string>,
            'local-port' <int>,
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
        Returns json if good, None otherwise
        """
        ret = {}
        #required for all peers
        requiredKeys = ['type', 'sender', 'local-ip', 'local-port']
        for key in requiredKeys:
            if key in jData:
                ret[key] = jData[key]
            else:
                message = "missing info from packet data: " + key
                self.sendError(self.makeGlobalAddress(jData), jData['sender'], message)
                return
        #required depending on type
        if jData['type'] == 'requesting-to-join-server':
            requiredKeys = ['server-name']
        elif jData['type'] == 'registering-server':
            requiredKeys = ['seconds-before-expiry']
        else:
            requiredKeys = []
        for key in requiredKeys:
            if key in jData:
                ret[key] = jData[key]
            else:
                message = "missing info from packet data: " + key
                self.sendError(self.makeGlobalAddress(jData), jData['sender'], message)
                return
        return ret    



    def makeHandshakeJson(self, jData):
        """
        Returns { 
            'type': 'providing-peer-handshake-info'
            'global-address': <address tuple>,  
            'local-address': <address tuple>,
            'peer-name': <string>
        }
        from a full json dict
        """
        ret = {}
        ret['type'] = 'providing-peer-handshake-info'
        ret['global-address'] = (jData['global-ip'], jData['global-port'])
        ret['local-address'] = (jData['local-ip'], jData['local-port'])
        ret['peer-name'] = jData['sender']
        return ret

    def makeGlobalAddress(self, jData):
        """joins jData['global-ip'] and jData['port'] into a tuple"""
        return (jData['global-ip'], jData['global-port'])

    def sendError(self, address, intendedRecipient, message):
        """sends a packet of type server-error"""
        data = {
                'type': 'server-error',
                'intended-recipient': intendedRecipient,
                'message': message
            }
        self.transport.write(json.dumps(data).encode(), address)

    def datagramReceived(self, datagram, address):
        """
        Handles incoming packets.
        """
        #binary -> string -> json dict
        data = json.loads(datagram.decode('utf-8'))
        print("received " + str(data) + " from " + address[0])

        jData['global-ip'] = address[0]
        jData['global-port'] = address[1]
        #gather the user info
        jData = self.validateData(data)
        if jData == None:
            print("ill-formed datagram")
            return
        
        #register server if that's what we're doing
        if jData['type'] == 'registering-server':
            #reject if a server exists with different address
            if jData['sender'] in self.serverHosts:
                existingAddress =  self.makeGlobalAddress(self.serverHosts[jData['sender']])
                newAddress = self.makeGlobalAddress(jData)
                if newAddress != existingAddress:
                    self.sendError(newAddress, jData['sender'], "server already exists")
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
                self.sendError(self.makeGlobalAddress(jData), jData['sender'], message)
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