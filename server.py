#!/usr/bin/env python
#based on: https://github.com/stylesuxx/udp-hole-punching
#great info here: http://www.brynosaurus.com/pub/net/p2pnat/
"""
    Handshake server for UDP hole-punching.
    Firewall must allow ingress and egress at SERVER_PORT = 5160
    Peers can send two kinds of messages:
        {
            'registering-server': True,
            'user-name': <unique string>
            'private-ip': <string>
            'private-port' <int>
        }
    registers a server peer under the name user-name, and
        {
            'registering-server': False,
            'user-name': <unique string>
            'private-ip': <string>
            'private-port' <int>
            'server-name': <unique string>
            'server-password': <string>
        }
    initiates a linking between the sender and the server peer registered user server-name.

    This intermediary server does this by sending each of the two peers the other peer's 
    private and public (garnered form the incoming message headers themselves) addresses.
    From there, it's up to the peers to hole-punch and link to each other.

    note: currently does not support server list refresh and doesn't even think about packet unreliability.

"""
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
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
        requiredKeys = ['registering-server', 'user-name', 'private-ip', 'private-port']
        for key in requiredKeys:
            if key in jData:
                ret[key] = jData[key]
            else:
                return
        #required for peers seeking to join a server
        if not jData['registering-server']:
            requiredKeys = ['server-name', 'server-password']
            for key in requiredKeys:
                if key in jData:
                    ret[key] = jData[key]
                else:
                    return
        return ret    



    def makeHandshakeJson(self, jData):
        """
        Returns { 
            'public-address': <address tuple>,  
            'private-address': <address tuple>,
            'user-name': <string>
        }
        from a full json dict
        """
        ret = {}
        ret['public-address'] = (jData['public-ip'], jData['public-port'])
        ret['private-address'] = (jData['private-ip'], jData['private-port'])
        ret['user-name'] = jData['user-name']
        if 'server-password' in jData.keys():
            ret['server-password'] = jData['server-password']
        return ret




    def datagramReceived(self, datagram, address):
        """
        Handles incoming packets.
        """
        #binary -> string -> json dict
        data = json.loads(datagram.decode('utf-8'))
        print("received " + str(data) + " from " + address[0])

        #gather the user info
        jData = self.validateData(data)
        if jData == None:
            print("ill-formed datagram")
            return
        jData['public-ip'] = address[0]
        jData['public-port'] = address[1]
        
        #register server if tat's what we're doing
        if jData['registering-server'] == True:
            #store the server by its user-name
            self.serverHosts[jData['user-name']] = jData
            print("server list updated.")
            print("    ->" + str(self.serverHosts))

        #otherwise, we're linking a server and a nonserver peer
        elif jData['registering-server'] == False:
            #check server exists
            print("joining " + jData['user-name'] + " and " + jData['server-name'])
            if not jData['server-name'] in self.serverHosts.keys():
                print(jData['server-name'] + " not found")
                return
            #make handshake messages
            serverJData = self.serverHosts[jData['server-name']]
            serverInfo = self.makeHandshakeJson(serverJData)
            clientInfo = self.makeHandshakeJson(jData)
            #send them out
            #beware that tuples become lists in json- peers will need to change them back to tuples
            self.transport.write(json.dumps(serverInfo).encode(), clientInfo['public-address'])
            self.transport.write(json.dumps(clientInfo).encode(), serverInfo['public-address'])
            print("sent linking info to " + jData['server-name'] + " and " + jData['user-name'])
        

if __name__ == '__main__':
    reactor.listenUDP(SERVER_PORT, ServerProtocol())
    reactor.run()