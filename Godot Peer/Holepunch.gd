extends Node

"""
todo: add X-scene support (eg a function that takes a bool (am i server) and confirmed peers
		and continues heartbeating and signallin etc.)
	: add passwords
	:documentation
"""


#############################################################
#############################################################
#                           SIGNALS                         #
#############################################################

signal peer_dropped
signal session_terminated 
signal packet_received
signal peer_confirmed
signal received_unreliable_message_from_peer
signal received_reliable_message_from_peer 
signal peer_confirmed_reliable_message_received
signal reliable_message_timeout
signal peer_check_timeout
signal peer_handshake_timeout
signal error
signal received_server_list

#############################################################
#############################################################
#                        CLASS VARIABLS                     #
#############################################################

const _SERVER_NAME = ""
const _secs_between_peer_checks = 15
var _user_name = null
var _i_am_server = null
var _peers = null
var _heartbeat_packets = HeartBeatPacketContainer.new()
var _socket = PacketPeerUDP.new()
var _seconds_ticker = 0
var _local_address = null
var _handshake_server = null
var _password = null
var _seconds_server_registration_valid
var _secs_between_registration_refresh


#############################################################
#############################################################
#          PROCESS HEARTBEATS AND INCOMING                  #
#############################################################


func generate_random_alpha_numeric(length):
	randomize()
	var random_string = str(randf())
	while random_string.length() < length:
		random_string += random_string
	return random_string.sha256_text().substr(0, length)


func check_security_incoming(packet, sender_address):
	"""
	returns null if validation failed. 
	Note: does not validate for specific types
	"""
	
	var json_string = packet.get_string_from_utf8()
	var result = JSON.parse(json_string)
	if result.error != OK:
		return null
	
	var jdata = result.result
	var peer 
	var is_valid = false
	if jdata.has('sender') and _peers.get(jdata['sender']):
		is_valid = _peers.get(jdata['sender']).check_security_incoming(jdata, sender_address)
	elif _handshake_server:
		is_valid = _handshake_server.check_security_incoming(jdata, sender_address)
	
	if is_valid:
		return jdata
	else:
		return null


func _process(delta):
	_seconds_ticker += delta
	if _seconds_ticker > 1:
		_seconds_ticker = 0
		if _heartbeat_packets:
			for packet in _heartbeat_packets.get_packets_array_copy():
				var packet_expired = packet.seconds_tick()
				if packet_expired:
					_heartbeat_packets.remove_all_of_peer_and_type(packet.peer_name, packet.type)
					if packet.type == 'requesting-server-list':
						emit_signal('error', 'failed to get list from server')
						return
					if packet.type == 'registering-server':
						quit_connection()
						return
					if packet.type == 'requesting-to-join-server':
						quit_connection()
						return
					if packet.type == 'local-global-inqury':
						emit_signal('peer_handshake_timeout', packet.peer_name)
						if _i_am_server:
							#we're not 'dropping' the peer because they were 
							#never really connected
							_peers.remove(packet.peer_name)
						else:
							quit_connection()
						return
					if packet.type == 'peer-check':
						emit_signal('peer_check_timeout', packet.peer_name)
						if _i_am_server:
							drop_peer(packet.peer_name)
						else:
							quit_connection()
						return
					if packet.type == 'reliable-peer-message':
						emit_signal('reliable_message_timeout', packet.get_copy_of_json_data())
						return
					else:
						quit_connection()
						return

	if _socket:
		while _socket.get_available_packet_count() > 0:
			#extract and validate
			var packet = _socket.get_packet()
			var sender_address = [_socket.get_packet_ip(), _socket.get_packet_port()]
			var jdata = check_security_incoming(packet, sender_address)
			if jdata == null:
				return
			emit_signal('packet_received', jdata.duplicate())
			
			#server errors should terminate the connection
			if jdata['type'] == 'server-error':
				emit_signal('error', jdata['message'])
				quit_connection()
				break
			
			#we got a reply of server lists from a handshake server
			elif jdata['type'] == 'providing-server-list':
				_heartbeat_packets.remove_all_of_type('requesting-server-list')
				var info = {
					'server-list': jdata['server-list'],
					'server-address': [_socket.get_packet_ip(), _socket.get_packet_port()]
				}
				emit_signal('received_server_list', info)
			
			#registration confirmation - only for server hosts
			elif jdata['type'] == 'confirming-registration':
				_heartbeat_packets.remove_all_of_peer_and_type(_SERVER_NAME, 'registering-server')
				var data = {
					'seconds-before-expiry': _seconds_server_registration_valid
				}
				var refresh = _handshake_server.make_heartbeat_packet('refreshing-server-registration',
																	  data, false, 
																	  _secs_between_registration_refresh)
				_heartbeat_packets.add(refresh)
				
			
			elif jdata['type'] == 'confirming-registration-refresh':
				_heartbeat_packets.reset_expiry_for_all_of_peer_and_type(_SERVER_NAME, 
																		'refreshing-server-registration')
			
			#from server - peer info we can use to join P2P
			elif jdata['type'] == 'providing-peer-handshake-info':
				#only matters if we asked to join but remove is forgiving
				_heartbeat_packets.remove_all_of_peer_and_type(_SERVER_NAME, 'requesting-to-join-server')
				#send out test packets to local and global addresses if we haven't already
				var peer_name = jdata['peer-name']
				if _peers.get(peer_name) == null:
					var peer = Peer.new(self._user_name, peer_name, _password, 
										self._socket, self._heartbeat_packets,
										jdata['global-address'], jdata['local-address'])
					_peers.add(peer)
					peer.send_address_inquiry()
			
			#inquiry from peer - we want to mirror back the successful packet
			elif jdata['type'] == 'local-global-inqury':
				#note we don't add this into heartbeat- we just bounce back whatever the
				#peer sends us. If it fails, they'll send again because it's in their heartbeat
				var address = [_socket.get_packet_ip(), _socket.get_packet_port()]
				var peer_name = jdata['sender']
				_peers.get(peer_name).make_packet('local-global-inquiry-response', jdata, address).send()
			
			#from peer - we have received the reflecion of the succesful inquiry
			elif jdata['type'] == 'local-global-inquiry-response':
				var peer_name = jdata['sender']
				_heartbeat_packets.remove_all_of_peer_and_type(peer_name, 'local-global-inqury')
				#check we know who this is but that a pervious inquiry response 
				#hasn't already come through (we want the fastest one)
				var peer = _peers.get(peer_name)
				if peer and not peer.is_confirmed():
					peer.confirm(jdata['used-global'])
					emit_signal('peer_confirmed', peer.info())
					var check = peer.make_heartbeat_packet('peer-check', {}, false, _secs_between_peer_checks)
					_heartbeat_packets.add(check)
			
			#sent from peer to keep connection open and check if we're still here
			elif jdata['type'] == 'peer-check':
				#send back a response
				var peer = _peers.get(jdata['sender'])
				if peer and peer.is_confirmed():
					peer.make_packet('peer-check-response', jdata).send()
			
			#sent by peer in response to peer check
			elif jdata['type'] == 'peer-check-response':
				_heartbeat_packets.reset_expiry_for_all_of_peer_and_type(jdata['sender'], 'peer-check')
			
			#unreliable message sent by peer
			elif jdata['type'] == 'unreliable-peer-message':
				emit_signal('received_unreliable_message_from_peer', jdata)
				
			#reliable message sent by peer
			elif jdata['type'] == 'reliable-peer-message':
				var peer = _peers.get(jdata['sender'])
				if peer and peer.is_confirmed():
					if not peer.msg_history_contains(jdata['message-id']):
						peer.add_id_to_msg_history(jdata['message-id'])
						emit_signal('received_reliable_message_from_peer', jdata)
					peer.make_packet('reliable-peer-message-response', jdata).send()
			
			#sent by peer confirming they have received our reliable message
			elif jdata['type'] == 'reliable-peer-message-response':
				var peer_name = jdata['sender']
				var type = 'reliable-peer-message'
				var key = 'message-id'
				var value = jdata['message-id']
				_heartbeat_packets.remove_all_of_peer_and_type_with_key_value(peer_name, type, key, value)
				emit_signal('peer_confirmed_reliable_message_received', jdata)



#############################################################
#############################################################
#                EXTERNALLY VISIBLE METHODS                 #
#############################################################

func get_user_name():
	return _user_name

func get_peers():
	if _peers != null:
		return _peers.get_confirmed()
	else:
		return null

func i_am_server():
	return _i_am_server

func send_unreliable_message_to_peer(peer_name, message):
	"""send a message and who cares if it gets there"""
	var peer = _peers.get(peer_name)
	if peer:
		peer.send_unreliable_message(message)
	else:
		emit_signal('error', 'no peer named ' + peer_name)


func send_reliable_message_to_peer(peer_name, message):
	"""send a message and care about whether it gets there"""
	var peer = _peers.get(peer_name)
	if peer:
		peer.send_reliable_message(message)
	else:
		emit_signal('error', 'no peer named ' + peer_name)

func request_server_list(handshake_address):
	"""requests server list from a handshake server"""
	if not _handshake_server or _handshake_server.address() != handshake_address:
		_heartbeat_packets.remove_all_of_peer(_SERVER_NAME)
		_handshake_server = Peer.new(_user_name, _SERVER_NAME, generate_random_alpha_numeric(10),
									  _socket, _heartbeat_packets, handshake_address)
									
	var data = {'password': _handshake_server.password()}
	_heartbeat_packets.add(	_handshake_server.make_heartbeat_packet('requesting-server-list', data))

func quit_connection():
	"""reset to an initial state with no peers"""
	_user_name = null
	_peers = null
	_i_am_server = null
	_handshake_server = null
	_heartbeat_packets = HeartBeatPacketContainer.new()
	_socket = PacketPeerUDP.new()
	_local_address = null
	_password = null
	_seconds_server_registration_valid = null
	_secs_between_registration_refresh = null
	emit_signal('session_terminated')


func drop_connection_with_handshake_server():
	"""after calling this, P2P is self-sustained"""
	_heartbeat_packets.remove_all_of_peer(_SERVER_NAME)
	_handshake_server = null


func drop_peer(peer_name):
	"""remove peer"""
	_heartbeat_packets.remove_all_of_peer(peer_name)
	var peer = _peers.get(peer_name)
	_peers.remove(peer_name)
	if peer:
		emit_signal('peer_dropped', peer_name)
	else:
		emit_signal('error', 'no peer named ' + peer_name)


func init_server(handshake_ip, handshake_port, local_ip, local_port, 
				 server_name, password=null, seconds_reg_valid=60, 
				 seconds_between_reg_refresh=15):
	if not _common_init(server_name, handshake_ip, handshake_port, local_ip, local_port):
		return 
	self._i_am_server = true
	self._seconds_server_registration_valid = seconds_reg_valid
	self._secs_between_registration_refresh = seconds_between_reg_refresh
	if not password:
		_password = server_name
	else:
		_password = password
	var data = {
		'local-address': self._local_address,
		'seconds-before-expiry': self._seconds_server_registration_valid,
		'password': _handshake_server.password()
	}
	#packet will be sent immediately
	var packet = _handshake_server.make_heartbeat_packet('registering-server', data, true)
	_heartbeat_packets.add(packet)
	
func init_client(handshake_ip, handshake_port, local_ip, local_port, user_name, server_name, password=null):
	if not _common_init(user_name, handshake_ip, handshake_port, local_ip, local_port):
		return
	self._i_am_server = false
	if not password:
		_password = server_name
	else:
		_password = password
	var data = {
		'local-address': self._local_address,
		'server-name': server_name,
		'password': _handshake_server.password()
	}
	#packet will be sent immediately
	var packet = _handshake_server.make_heartbeat_packet('requesting-to-join-server', data, true)
	_heartbeat_packets.add(packet)


#############################################################
#############################################################
#                        HELPER METHODS                     #
#############################################################

func _common_init(user_name, handshake_ip, handshake_port, local_ip, local_port):
	"""set up most of the initial variables. Returns false on failure"""
	if user_name == _SERVER_NAME:
		emit_signal('error', 'invalid user name: ' + user_name)
		return false
	_local_address = [local_ip, int(local_port)]	
	_socket = PacketPeerUDP.new()
	_heartbeat_packets = HeartBeatPacketContainer.new()
	_user_name = user_name
	_peers = PeerContainer.new()
	var handshake_address = [handshake_ip, int(handshake_port)]
	_handshake_server = Peer.new(_user_name, _SERVER_NAME, generate_random_alpha_numeric(10),
									  _socket, _heartbeat_packets, handshake_address)
		
	if _socket.listen(local_port) != OK:
		quit_connection()
		emit_signal('error', 'invalid listener port')
		return false
	return true








#############################################################
#############################################################
#                        PACKET CLASSES                     #
#       use peers - NOT the Packet or HeartbeatPackets      #
#############################################################




#don't use the Packet class directly - use peers
class Packet:
	"""
	Stores enough information about a packet to provide a simple send() function
	"""
	var peer_name #destination peer
	var address #[ip, port] as [<string>, <int>]
	var type
	var _socket
	var _data_as_json

	func _init(user_name, peer_name, _socket, address, type, data_as_json):
		"""adds the type, sender and recipient to the data to be sent"""
		self.peer_name = peer_name
		self.type = type
		self.address = address
		self._socket = _socket
		self._data_as_json = data_as_json
		
		
	func get_copy_of_json_data():
		return _data_as_json.duplicate()
	
	func send():
		var bin_data = JSON.print(self._data_as_json).to_utf8()
		self._socket.set_dest_address(address[0], address[1])
		self._socket.put_packet(bin_data)

#don't use the HeartbeatPacket class directly - use peers
class HeartbeatPacket extends Packet:
	"""
	Call self.seconds_tick() every second, and call self.reset_expiry() when 
	a reply comes in. self.seconds_tick() returns true if the packet has expired.
	Stores a packet to be sent with self.seconds_between_resends (null for no no repeat). 
	Every time it's sent, it will wait self.seconds_to_await_reply before
	giving up on receiving a reply. After self.attempts_before_expiration failures,
	the packet will expire. 
	"""
	var _resend_countdown
	var _await_reply_countdown
	var _attempts_countdown
	var _attempts_before_expiration
	var _seconds_to_await_reply
	var _seconds_between_resends #set -1 to never resend 
	var _awaiting_reply = false
	var _sent_once_already = false
	#goes to shit if if not send_immediately and seconds_between_resends == null:
	func _init(user_name, peer_name, _socket, address, type, data_as_json, 
				send_immediately=true, seconds_between_resends=null,
				seconds_to_await_reply=1,
				attempts_before_expiration=5).(user_name, peer_name, 
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
			self._sent_once_already = true
			
	func seconds_tick():
		"""
		Returns true if the packet has expired
		"""
		if _awaiting_reply:
			_await_reply_countdown -= 1
			if _await_reply_countdown <= 0:
				print("attempt failed")
				_attempts_countdown -= 1
				if _attempts_countdown <= 0:
					print("packet expired")
					return true
				else:
					_await_reply_countdown = _seconds_to_await_reply
					print("attempt to resend type: " + type)
					send()
		
		elif _seconds_between_resends != null or not _sent_once_already:
			_resend_countdown -= 1
			if _resend_countdown <= 0:
				#reset the expiration counters and send the packet
				print("sent type: " + type)
				send()
				reset_expiry()
				_awaiting_reply = true
				_sent_once_already = true
		#the packet hasn't expired
		return false

	func reset_expiry():
		_awaiting_reply = false
		_attempts_countdown = _attempts_before_expiration
		_await_reply_countdown = _seconds_to_await_reply
		_resend_countdown = _seconds_between_resends

class HeartBeatPacketContainer:
	"""
	Used to store and manage heartbeat packets.
	"""
	var _packets = []
	
	func add(packet, replace_same_peer_and_type = true):
		"""add a heartbeat packet"""
		if replace_same_peer_and_type:
			remove_all_of_peer_and_type(packet.peer_name, packet.type)
		_packets.push_back(packet)
	
	func remove_all_of_peer(peer_name):
		"""removes all packets directed to a given peer"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name:
				_packets.erase(packet)
	
	func remove_all_of_type(type):
		"""removes all packets of a given type"""
		for packet in _packets.duplicate():
			if packet.type == type:
				_packets.erase(packet)
	
	func remove_all_of_peer_and_type(peer_name, type):
		"""remove all packets that match peer AND type"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name and packet.type == type:
				_packets.erase(packet)
	
	func remove_all_of_peer_and_type_with_key_value(peer_name, type, key, value):
		"""remove all packets that match peer AND type AND that have a key with value"""
		for packet in _packets.duplicate():
			if packet.peer_name == peer_name:
				print('match peer name')
				print('"'+packet.type+'" vs "'+type+'"')
				if packet.type == type:
					print('match type')
					var data = packet.get_copy_of_json_data()
					if data.has(key) and data[key] == value:
							_packets.erase(packet)
			
	func reset_expiry_for_all_of_peer(peer_name):
		"""reset all expiry counters packets for a given peer"""
		for packet in _packets:
			if packet.peer_name == peer_name:
				packet.reset_expiry()
				
	func reset_expiry_for_all_of_peer_and_type(peer_name, type):
		"""reset all packets that match peer AND type"""
		for packet in _packets:
			if packet.peer_name == peer_name and packet.type == type:
				packet.reset_expiry()
				
	func get_packets_array_copy():
		"""returns a copy of the underlying array"""
		return _packets.duplicate()
		
	func clear():
		_packets = []















#############################################################
#############################################################
#                        PEER CLASSES                       #
#############################################################
#This has to come after the packet classes or reference errors materialise

class Peer:
	var _peer_name = null
	var _your_name = null
	var _local_address = null
	var _global_address = null
	var _password = null
	var _ids_of_received_messaged = []
	var _use_global = 'undecided'
	var _sent_message_id_counter = 0
	var _socket = null
	var _heartbeat_container = null
	var _i_am_handshake_server = null
	func _init(your_name, peer_name, password, socket, heartbeat_container, 
				global_address, local_address=null):
		self._your_name = your_name
		self._peer_name = peer_name
		self._password = password
		self._socket = socket
		self._heartbeat_container = heartbeat_container
		self._i_am_handshake_server = peer_name == _SERVER_NAME
		self._global_address = [global_address[0], int(global_address[1])]
		if local_address:
			self._local_address = [local_address[0], int(local_address[1])]
		else:
			confirm(true)
	func name():
		return _peer_name
	func your_name():
		return _your_name
	func password():
		return _password
	func socket():
		return _socket
	func info():
		if is_confirmed():
			return {'name': name(), 'address': address()}
		else:
			return {'name': name(), 'local-address': local_address(), 
									'global-address': global_address()}
	
	func confirm(use_global):
		self._use_global = use_global
	func is_confirmed():
		return typeof(_use_global) != TYPE_STRING
	
	func global_address():
		return _global_address
	func local_address():
		return _local_address
	func address():
		if not is_confirmed():
			return null
		if _use_global:
			return global_address()
		else:
			return local_address()
	
	func send_address_inquiry():
		var g_data = {'used-global': true}
		_heartbeat_container.add(make_heartbeat_packet('local-global-inqury', g_data, 
								 true, null, global_address()))
		var l_data = {'used-global': false}
		_heartbeat_container.add(make_heartbeat_packet('local-global-inqury', l_data, 
								 true, null, local_address()))
		
	func send_reliable_message(message):
		"""true if message send attempted"""
		if not is_confirmed():
			return false
		var data = {
			'message': message,
			'message-id': self._get_unique_msg_id()
		}
		var packet = make_heartbeat_packet('reliable-peer-message', data, true) 
		_heartbeat_container.add(packet, false)
		return true
		
	func send_unreliable_message(message):
		"""true if message send attempted"""
		if not is_confirmed():
			return false
		make_packet('unreliable-peer-message', {'message': message}).send()
		return true

	func _get_unique_msg_id():
		var ret = _sent_message_id_counter
		_sent_message_id_counter += 1
		#if it gets to this point a LOT of messages must have been sent
		if _sent_message_id_counter < 0:
			_sent_message_id_counter = 0
		return ret
	
	func add_id_to_msg_history(msg_id):
		_ids_of_received_messaged.push_back(msg_id)
		if _ids_of_received_messaged.size() > 50:
			#there's actually no better way to do this yet... would prefer [-10:]
			var new_array = []
			for i in range(25, _ids_of_received_messaged.size()):
				new_array.push_back(_ids_of_received_messaged[i])
			_ids_of_received_messaged = new_array
	
	func msg_history_contains(msg_id):
		return _ids_of_received_messaged.has(msg_id)
	
	func make_packet(type, data, custom_address=null):
		data = _add_security_outgoing(type, data)
		if custom_address:
			return Packet.new(your_name(), name(), socket(), custom_address, type, data)
		else:
			return Packet.new(your_name(), name(), socket(), address(), type, data)
		
	func make_heartbeat_packet(type, data, send_immediately=true, seconds_between_resends=null, 
							   custom_address=null):
		data = _add_security_outgoing(type, data)
		if custom_address:
			return HeartbeatPacket.new(your_name(), name(), socket(), custom_address, type, data, 
										send_immediately, seconds_between_resends)
		else:
			return HeartbeatPacket.new(your_name(), name(), socket(), address(), type, data, 
										send_immediately, seconds_between_resends)
	
	func _get_sorted_joined_string_elements_from_array(array):
		var array_copy = []
		for key in array:
			if typeof(key) == TYPE_STRING:
				array_copy.push_back(key)
		array_copy.sort()
		var string_of_sorted_strings = ''
		for key in array_copy:
				string_of_sorted_strings += key
		return string_of_sorted_strings
		
	func _add_security_outgoing(type, data):
		data['type'] = type
		data['sender'] = your_name()
		data['intended-recipient'] = name()
		var data_copy = data.duplicate()
		data_copy['password'] = password()
		var jstring = _get_sorted_joined_string_elements_from_array(data_copy.keys())
		jstring += _get_sorted_joined_string_elements_from_array(data_copy.values())

		var hash_string =jstring.sha256_text()
		
		data['hash-string'] = hash_string
		return data
		
	func check_security_incoming(jdata, sender_address):
		print('incoming')
		print('sender calculations : ' + jdata['hash-string'])
		if is_confirmed() and sender_address != address():
			return false
		elif sender_address != local_address() and sender_address != global_address():
			return false

		if not jdata.has('intended-recipient') or jdata['intended-recipient'] != your_name():
			return false
		if not jdata.has('hash-string'):
			return false
		var sender_hash = jdata['hash-string']
		jdata.erase('hash-string')
		var jdata_copy = jdata.duplicate()
		jdata_copy['password'] = password()
		
		var jstring = _get_sorted_joined_string_elements_from_array(jdata_copy.keys())
		jstring += _get_sorted_joined_string_elements_from_array(jdata_copy.values())

		var hash_string =jstring.sha256_text()
		print('my calculations: ' + hash_string)

		
		return hash_string == sender_hash
		
	






















































class PeerContainer:
	var _peers = {}
	func get(peer_name):
		if _peers.has(peer_name):
			return _peers[peer_name]
		return null
	func get_confirmed():
		var ret = []
		for peer in _peers.values():
			if peer.is_confirmed():
				ret.push_back(peer.info())
		return ret
	func get_unconfirmed():
		var ret = []
		for peer in _peers.values():
			if not peer.is_confirmed():
				ret.push_back(peer.info())
		return ret
	func add(peer):
		_peers[peer.name()] = peer
	func remove(peer_name):
		if _peers.has(peer_name):
			_peers.erase(peer_name)
















