extends Node

signal peer_dropped #, peer_name
signal connection_lost #, server?
signal packet_received #, jData
signal peer_confirmed #, {peer-name, address}}
signal message_from_peer # jData
signal error # <string> message

#create some wide-scope variables
var user_name = null
var i_am_server = null

var confirmed_peers = {}
var _unconfirmed_peers = {}
var _heartbeat_packets = _HeartBeatPacketContainer.new()
var _socket = null
var _seconds_ticker = 0
#set false when we don't care what the server is sending us
var _quit_on_handshake_server_error = true 
#keep null to differentiate between it and other peers
const _SERVER_NAME = null
var _local_ip = null
var _local_port = null

func _process(delta):
	_seconds_ticker += delta
	if _seconds_ticker > 1:
		#code in here happens once a second
		_seconds_ticker = 0
		for packet in _heartbeat_packets.get_packets_array_copy():
			var packet_expired = packet.seconds_tick()
			if packet_expired:
				#non-servers should just give up
				if not i_am_server:
					quit_connection()
					emit_signal('connection_lost', false)
					return
				#servers should give up if they were trying to register
				#otherwise it may just be that peer, so boot them
				else:
					if packet.type == 'registering-server':
						quit_connection()
						emit_signal('connection_lost', true)
						return
					else:
						drop_peer(packet.peer_name)
	
	#process messages
	if _socket:
		while _socket.get_available_packet_count() > 0:
			var jData = _get_var_from_bytes(_socket.get_packet())
			if not jData.has('intended-recipient') or jData['intended-recipient'] != user_name:
				return
			emit_signal('packet_received', jData.duplicate())
			
			#server errors should terminate the connection
			#set _quit_on_server_error to false if we don't care what the server is sending us
			if jData['type'] == 'server-error':
				if _quit_on_handshake_server_error:
					quit_connection()
					emit_signal('error', jData['message'])
			
			#registration confirmation - only for server hosts
			elif jData['type'] == 'confirming-registration':
				_heartbeat_packets.reset_expiry(_SERVER_NAME, 'registering-server')
			
			#from server - the info of a peer to join with
			elif jData['type'] == 'providing-peer-handshake-info':
				#remove the request packet from the heartbeat
				if not i_am_server:
					_heartbeat_packets.remove(_SERVER_NAME, 'requesting-to-join-server')
				#send out test packets to local and global addresses
				#if we haven't already
				var peer_name = jData['peer-name']
				if not confirmed_peers.has(peer_name):
					if not _unconfirmed_peers.has(peer_name):
						jData['global-address'] = [jData['global-address'][0], 
												   int(jData['global-address'][1])]
						jData['local-address'] = [jData['local-address'][0], 
												   int(jData['local-address'][1])]
						#send global-address query
						var g_data = {'used-global': true}
						_heartbeat_packets.add(HeartbeatPacket.new(self.user_name, peer_name, 
											   _socket, jData['global-address'],
											   'local-global-inqury', g_data, 15, true))
						#send local-address query
						var l_data = {'used-global': false}
						_heartbeat_packets.add(HeartbeatPacket.new(self.user_name, peer_name, 
											   _socket, jData['local-address'],
										 	   'local-global-inqury', l_data, 15, true))
						#add as uncomfirmed
						_unconfirmed_peers[peer_name] = jData
			
			#from peer - we want to mirror back the successful packet
			elif jData['type'] == 'local-global-inqury':
				#note we don't add this into heartbeat- we just bounce back whatever the
				#peer sends us. If it fails, they'll send again because it's in their heartbeat
				var address = [_socket.get_packet_ip(), _socket.get_packet_port()]
				#jData will get overwritten with the correct sender info
				var mirrored = Packet.new(self.user_name, jData['sender'], _socket, address,
										  'local-global-inquiry-response', jData)
				mirrored.send()
			
			#from peer - the reflecion of the succesful inquiry
			elif jData['type'] == 'local-global-inquiry-response':
				var peer_name = jData['sender']
				_heartbeat_packets.remove(peer_name, 'local-global-inqury')
				#check we know who this is
				if _unconfirmed_peers.has(peer_name):
					var successful_address = null
					#remove the inquiry from the heartbeat
					#add as a confirmed peer
					if jData['used-global']:
						successful_address = _unconfirmed_peers[peer_name]['global-address']
					else:
						successful_address = _unconfirmed_peers[peer_name]['local-address']
					confirmed_peers[jData['sender']] = {
						'peer-name': peer_name, 
						'address': successful_address
					}
					emit_signal('peer_confirmed', confirmed_peers[jData['sender']].duplicate())
					_heartbeat_packets.add(HeartbeatPacket.new(self.user_name, peer_name, 
															  _socket, successful_address,
											  				  'peer-check', {}, 15, false))
			
			#sent from peer to keep connection open and check if we'e still here
			elif jData['type'] == 'peer-check':
				#send back a response
				var peer_name = jData['sender'] 
				if confirmed_peers.has(peer_name):
					var address = confirmed_peers[peer_name]['address']
					var mirrored = Packet.new(self.user_name, peer_name, _socket, address,
										  'peer-check-response', jData)
					mirrored.send()
			
			#sent by peer in response to peer check
			elif jData['type'] == 'peer-check-response':
				_heartbeat_packets.reset_expiry(jData['sender'], 'peer-check')
			
			#sent by peer- contains a message
			elif jData['type'] == 'peer-message':
				emit_signal('message_from_peer', jData)


func quit_connection():
	user_name = null
	confirmed_peers = {}
	
	_heartbeat_packets.clear()
	_socket = null
	_local_ip = null
	_local_port = null
	_unconfirmed_peers = {}


func drop_connection_with_handshake_server():
	_quit_on_handshake_server_error = false

func drop_peer(peer_name):
	_heartbeat_packets.remove_peer(peer_name)
	if _unconfirmed_peers.has(peer_name):
		_unconfirmed_peers.erase(peer_name)
	if confirmed_peers.has(peer_name):
		confirmed_peers.erase(peer_name)
	emit_signal('peer_dropped', peer_name)


func init_server(handshake_ip, handshake_port, local_ip, local_port, 
				 server_name, seconds_registration_valid=60, 
				 registration_refresh_rate=15):
	_socket = PacketPeerUDP.new()
	if _socket.listen(local_port) != OK:
		emit_signal('error', 'invalid listener port')
		return
	self.user_name = server_name
	self.i_am_server = true
	var data = {
		'type': 'registering-server',
		'local-ip': local_ip,
		'local-port': local_port,
		'seconds-before-expiry': seconds_registration_valid
	}
	#packet will be sent immediately, and every 15 seconds
	var address = [handshake_ip, handshake_port]
	var packet = HeartbeatPacket.new(self.user_name, _SERVER_NAME, _socket, address,
									 'registering-server', data, registration_refresh_rate, true)
	_heartbeat_packets.add(packet)
	
func init_client(handshake_ip, handshake_port, local_ip, local_port, user_name, server_name):
	_socket = PacketPeerUDP.new()
	if _socket.listen(local_port) != OK:
		return
	self.user_name = user_name
	self.i_am_server = false
	var data = {
		'type': 'requesting-to-join-server',
		'local-ip': local_ip,
		'local-port': local_port,
		'server_name': server_name
	}
	#packet will be sent immediately, and every 15 seconds
	var address = [handshake_ip, handshake_port]
	var packet = HeartbeatPacket.new(self.user_name, _SERVER_NAME, _socket, address,
									 'requesting-to-join-server', data, -1, true)
	_heartbeat_packets.add(packet)




func send_unreliable_message_to_peer(peer_name, message):
	if self.user_name != null and confirmed_peers.has(peer_name):
		var data = {
			'message': message
		}
		var address = confirmed_peers[peer_name]['address']
		var packet = Packet.new(self.user_name, peer_name, _socket, address,
								  'peer-message', data)
		packet.send()


func _get_var_from_bytes(array_bytes):
	"""array_bytes -> string -> json"""
	var json_string = array_bytes.get_string_from_utf8()
	return JSON.parse(json_string).result

#############################################################
#############################################################
#                        HELPER CLASSES                     #
#############################################################

class Packet:
	"""
	Stores enough information about a packet to provide a simple send() function
	"""
	var peer_name #destination peer
	var _socket
	var address #[ip, port] as [<string>, <int>]
	var data_as_json
	var type #e.g. 'registering-server'
	
	
	func _init(user_name, peer_name, _socket, address, type, data_as_json):
		"""adds the type to the data to be sent"""
		self.peer_name = peer_name
		self._socket = _socket
		self.address = address
		self.data_as_json = data_as_json
		self.data_as_json['type'] = type
		self.data_as_json['sender'] = user_name
		self.data_as_json['intended-recipient'] = peer_name
		self.type = type
	func send():
		var bin_data = JSON.print(self.data_as_json).to_utf8()
		self._socket.set_dest_address(address[0], address[1])
		self._socket.put_packet(bin_data)

class HeartbeatPacket extends Packet:
	"""
	Call self.seconds_tick() every second, and call self.reset_expiry() when 
	a reply comes in. self.seconds_tick() returns true if the packet has expired.
	Stores a packet to be sent every self.seconds_between_resends seconds. 
	Every time it's sent, it will wait self.seconds_to_await_reply before
	giving up on receiving a reply. After self.attempts_before_expiration failures,
	the packet will expire. 
	"""
	var _resend_countdown
	var _await_reply_countdown
	var _attempts_countdown
	var _attempts_before_expiration
	var _seconds_to_await_reply
	var _seconds_between_resends
	var _awaiting_reply = false
	func _init(user_name, peer_name, _socket, address, type, data_as_json, 
				seconds_between_resends, send_immediately=false, 
				seconds_to_await_reply=1,
				attempts_before_expiration=3).(user_name, peer_name, 
												_socket, address, type, 
												data_as_json):
		self._seconds_between_resends = seconds_between_resends
		self._resend_countdown = seconds_between_resends
		self._seconds_to_await_reply = seconds_to_await_reply
		self._await_reply_countdown = seconds_to_await_reply
		self._attempts_before_expiration = attempts_before_expiration
		self._attempts_countdown = attempts_before_expiration
		if send_immediately:
			send()
			self._awaiting_reply = true
			
	func seconds_tick():
		"""
		Returns true if the packet has expired
		"""
		if _awaiting_reply:
			_await_reply_countdown -= 1
			if _await_reply_countdown <= 0:
				print("attempt failed")
				_attempts_countdown -= 1
				#if we're run out of attempts, we expire
				if _attempts_countdown <= 0:
					print("packet expired")
					return true
				#otherwise we retry sending the packet and waiting
				else:
					_await_reply_countdown = _seconds_to_await_reply
					send()
		else:
			_resend_countdown -= 1
			if _resend_countdown <= 0:
				#reset the expiration counters and send the packet
				print("sent")
				send()
				reset_expiry()
				_awaiting_reply = true
		#the packet hasn't expired
		return false

	func reset_expiry():
		"""called when a reply has come io this packet"""
		_awaiting_reply = false
		_attempts_countdown = _attempts_before_expiration
		_await_reply_countdown = _seconds_to_await_reply
		_resend_countdown = _seconds_between_resends

class _HeartBeatPacketContainer:
	"""
	Used to store and manage heartbeat packets.
	"""
	var _packets = []
	
	func add(packet):
		"""add a heartbeat packet."""
		_packets.push_back(packet)
	
	func remove_peer(peer_name):
		"""removes all packets directed to a given peer"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name:
				_packets.erase(packet)
	func remove(peer_name, type):
		"""remove all packets for a given peer and type"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name and packet.type == type:
				_packets.erase(packet)
	
	func reset_expiry_for_peer(peer_name):
		"""reset all packets for a given peer"""
		for packet in _packets:
			if packet.peer_name == peer_name:
				packet.reset_expiry()
				
	func reset_expiry(peer_name, type):
		"""reset all packets for a given peer and type"""
		for packet in _packets:
			if packet.peer_name == peer_name and packet.type == type:
				packet.reset_expiry()
				
	func get_packets_array_copy():
		"""returns a copy of the underlying array"""
		return _packets.duplicate()
		
	func clear():
		_packets = []