extends Node

"""
todo: add X-scene support (eg a function that takes a bool (am i server) and confirmed peers
		and continues heartbeating and signallin etc.)
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
const secs_between_peer_checks = 15
const seconds_reg_valid = 60 
const seconds_between_reg_refresh = 15
const seconds_to_await_reply = 1
const attempts_before_expiration = 5

const _SERVER_NAME = "HANDSHAKE_SERVER"
var _user_name = null
var _i_am_server = null
var _peers = null
var _heartbeat_packets = HeartBeatPacketContainer.new()
var _socket = PacketPeerUDP.new()
var _local_address = null
var _handshake_server = null
var _password = null
var _seconds_server_registration_valid
var _secs_between_registration_refresh
var _seconds_ticker = 0




#############################################################
#############################################################
#          PROCESS HEARTBEATS AND INCOMING                  #
#############################################################

func _process(delta):
	_seconds_ticker += delta
	if _seconds_ticker > 1:
		_seconds_ticker = 0
		#copy because we remove packets from _heartbeat_packets within loop
		for packet in _heartbeat_packets.get_packets_array_copy():
			var packet_expired = packet.seconds_tick()
			if packet_expired:
				_heartbeat_packets.remove_all_of_peer_and_type(packet.dest_name, packet.type)
				if packet.type == 'requesting-server-list':
					emit_signal('error', 'failed to get list from server')
					return
				if packet.type == 'registering-server':
					quit_connection()
					return
				if packet.type == 'requesting-to-join-server':
					quit_connection()
					return
				if packet.type == 'address-inquiry':
					emit_signal('peer_handshake_timeout', packet.dest_name)
					if _i_am_server:
						#no official peer drop here- they were never really connected
						_peers.remove(packet.dest_name)
					else:
						quit_connection()
					return
				if packet.type == 'peer-check':
					emit_signal('peer_check_timeout', packet.dest_name)
					if _i_am_server:
						drop_peer(packet.dest_name)
					else:
						quit_connection()
					return
				if packet.type == 'reliable-peer-message':
					emit_signal('reliable_message_timeout', packet.get_copy_of_json_data())
					return
				else:
					quit_connection()
					return

	while _socket.get_available_packet_count() > 0:
		var packet = _get_incoming_packet()
		if packet == null:
			return
		var packet_data =  packet.get_copy_of_json_data()
		emit_signal('packet_received', packet.get_copy_of_json_data())
		
		if packet.type == 'server-error':
			emit_signal('error', packet_data['message'])
			quit_connection()
			break
		
		elif packet.type == 'providing-server-list':
			_heartbeat_packets.remove_all_of_type('requesting-server-list')
			var info = {
				'server-list': packet_data['server-list'],
				'server-address': packet.sender_address
			}
			emit_signal('received_server_list', info)
		
		elif packet.type == 'confirming-registration':
			_heartbeat_packets.remove_all_of_type('registering-server')
			var data = {
				'seconds-before-expiry': seconds_reg_valid
			}
			var send_immediately = false
			var refresh = _handshake_server.make_heartbeat_packet('refreshing-server-registration',
																  data, send_immediately, 
																  seconds_between_reg_refresh)
			_heartbeat_packets.add(refresh)
		
		elif packet.type == 'confirming-registration-refresh':
			_heartbeat_packets.reset_expiry_for_all_of_type('refreshing-server-registration')
		
		elif packet.type == 'providing-peer-handshake-info':
			#remove ignores if there are none matching
			_heartbeat_packets.remove_all_of_type('requesting-to-join-server')
			var peer_name = packet_data['peer-name']
			#only add if we haven't already
			if _peers.get(peer_name) == null:
				var peer = Peer.new(self._user_name, peer_name, _password, 
									self._socket, self._heartbeat_packets,
									packet_data['global-address'], packet_data['local-address'])
				_peers.add(peer)
				peer.send_address_inquiry()
		
		elif packet.type == 'address-inquiry':
			#If this fails, they'll send again because it's in THEIR heartbeat
			var peer_name = packet.sender_name
			var address = packet.sender_address
			_peers.get(peer_name).make_packet('address-inquiry-response', packet_data, address).send()
		
		elif packet.type == 'address-inquiry-response':
			_heartbeat_packets.remove_all_of_peer_and_type(packet.sender_name, 'address-inquiry')
			var peer = _peers.get(packet.sender_name)
			if peer and not peer.is_confirmed():
				peer.confirm(packet_data['used-global'])
				emit_signal('peer_confirmed', peer.info())
				var send_immediately = false
				var peer_check = peer.make_heartbeat_packet('peer-check', {}, send_immediately, 
														secs_between_peer_checks)
				_heartbeat_packets.add(peer_check)
		
		elif packet.type == 'peer-check':
			#If this fails, they'll send again because it's in THEIR heartbeat
			var peer = _peers.get(packet.sender_name)
			if peer and peer.is_confirmed():
				peer.make_packet('peer-check-response', packet_data).send()
		
		elif packet.type == 'peer-check-response':
			_heartbeat_packets.reset_expiry_for_all_of_peer_and_type(packet.sender_name, 'peer-check')
		
		elif packet.type == 'unreliable-peer-message':
			emit_signal('received_unreliable_message_from_peer', packet.get_copy_of_json_data())
			
		elif packet.type == 'reliable-peer-message':
			var peer = _peers.get(packet.sender_name)
			if peer and peer.is_confirmed():
				if not peer.msg_history_contains(packet_data['message-id']):
					peer.add_id_to_msg_history(packet_data['message-id'])
					emit_signal('received_reliable_message_from_peer', packet.get_copy_of_json_data())
				#If this fails, they'll send again because it's in THEIR heartbeat
				peer.make_packet('reliable-peer-message-response', packet_data).send()
		
		elif packet.type == 'reliable-peer-message-response':
			var type = 'reliable-peer-message'
			var key = 'message-id'
			var value = packet_data['message-id']
			_heartbeat_packets.remove_all_of_peer_and_type_with_key_value(packet.sender_name, type, 
																		  key, value)
			emit_signal('peer_confirmed_reliable_message_received', packet.get_copy_of_json_data())



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
		return []

func i_am_server():
	return _i_am_server

func send_unreliable_message_to_peer(peer_name, message):
	var peer = _peers.get(peer_name)
	if peer:
		peer.send_unreliable_message(message)
	else:
		emit_signal('error', 'no peer named ' + peer_name)


func send_reliable_message_to_peer(peer_name, message):
	var peer = _peers.get(peer_name)
	if peer:
		peer.send_reliable_message(message)
	else:
		emit_signal('error', 'no peer named ' + peer_name)

func request_server_list(handshake_address):
	if not _handshake_server or _handshake_server.address() != handshake_address:
		_heartbeat_packets.remove_all_of_peer(_SERVER_NAME)
		_handshake_server = Peer.new(_user_name, _SERVER_NAME, _generate_random_alpha_numeric(10),
									  _socket, _heartbeat_packets, handshake_address)
	var data = {'password': _handshake_server.password()}
	_heartbeat_packets.add(_handshake_server.make_heartbeat_packet('requesting-server-list', data))

func quit_connection():
	_user_name = null
	_peers = null
	_i_am_server = null
	_handshake_server = null
	_local_address = null
	_password = null
	_seconds_server_registration_valid = null
	_secs_between_registration_refresh = null
	_heartbeat_packets = HeartBeatPacketContainer.new()
	_socket = PacketPeerUDP.new()
	emit_signal('session_terminated')

func drop_connection_with_handshake_server():
	_heartbeat_packets.remove_all_of_peer(_SERVER_NAME)
	_handshake_server = null

func drop_peer(peer_name):
	_heartbeat_packets.remove_all_of_peer(peer_name)
	var peer = _peers.get(peer_name)
	_peers.remove(peer_name)
	if peer:
		emit_signal('peer_dropped', peer_name)
	else:
		emit_signal('error', 'no peer named ' + peer_name)

func init_server(handshake_address, local_address, server_name, password=null):
	if not _common_init(server_name, handshake_address, local_address):
		return 
	self._i_am_server = true
	self._password = password
	if not self._password:
		_password = server_name
	var data = {
		'local-address': self._local_address,
		'seconds-before-expiry': self.seconds_reg_valid,
		'password': _handshake_server.password()
	}
	var send_immediately = true
	var packet = _handshake_server.make_heartbeat_packet('registering-server', data, send_immediately)
	_heartbeat_packets.add(packet)
	
func init_client(handshake_address, local_address, user_name, server_name, password=null):
	if not _common_init(user_name, handshake_address, local_address):
		return
	self._i_am_server = false
	self._password = password
	if not self._password:
		_password = server_name
	var data = {
		'local-address': self._local_address,
		'server-name': server_name,
		'password': _handshake_server.password()
	}
	var send_immediately = true
	var packet = _handshake_server.make_heartbeat_packet('requesting-to-join-server', data, send_immediately)
	_heartbeat_packets.add(packet)


#############################################################
#############################################################
#                        HELPER METHODS                     #
#############################################################

func _common_init(user_name, handshake_address, local_address):
	if user_name == _SERVER_NAME or user_name == "":
		emit_signal('error', 'invalid user name: "' + user_name + '"')
		return false
	_user_name = user_name
	_local_address = [local_address[0], int(local_address[1])]
	_socket = PacketPeerUDP.new()
	_heartbeat_packets = HeartBeatPacketContainer.new()
	_peers = PeerContainer.new()
	handshake_address = [handshake_address[0], int(handshake_address[1])]
	_handshake_server = Peer.new(user_name, _SERVER_NAME, _generate_random_alpha_numeric(10),
									  _socket, _heartbeat_packets, handshake_address)
	if _socket.listen(_local_address[1]) != OK:
		emit_signal('error', 'invalid listener port')
		quit_connection()
		return false
	return true


func _generate_random_alpha_numeric(length):
	#only uses hex digits as characters for now
	randomize()
	var seeder_string = str(randf())
	var random_string = seeder_string.sha256_text()
	while random_string.length() < length:
		seeder_string = str(randf())
		random_string += seeder_string.sha256_text()
	return random_string.substr(0, length)


func _get_incoming_packet():
	var bytes = _socket.get_packet()
	var sender_address = [_socket.get_packet_ip(), _socket.get_packet_port()]
	
	var json_string = bytes.get_string_from_utf8()
	var result = JSON.parse(json_string)
	if result.error != OK:
		return null
	
	var jdata = result.result
	var peer 
	if jdata.has('sender') and _peers.get(jdata['sender']):
		peer = _peers.get(jdata['sender'])
	elif _handshake_server:
		peer = _handshake_server
	if not peer:
		return null
	return peer.check_security_and_make_incoming_packet(jdata, sender_address)


func _peer_sent_packet(packet):
	"""change to approproate signal later- just tetsing for now"""
	emit_signal('error', packet.type)


#############################################################
#############################################################
#                        PACKET CLASSES                     #
#       use peers - NOT the Packet or HeartbeatPackets      #
#############################################################


class Packet:
	"""
	Stores enough information about a packet to provide a simple send() function.
	You can only send outgoing packets
	"""
	var sender_name
	var dest_name
	var type
	#one of these two will be null, depending on is_outgoing
	var sender_address
	var dest_address
	var _socket
	var _data_as_json

	func _init(sender_name, dest_name, _socket, address, is_outgoing, type, data_as_json):
		self.sender_name = sender_name
		self.dest_name = dest_name
		self.type = type
		if is_outgoing:
			self.dest_address = address
		else:
			self.sender_address = address
		self._socket = _socket
		self._data_as_json = data_as_json
	
	func get_copy_of_json_data():
		return _data_as_json.duplicate()
	
	func send():
		if dest_address:
			var bin_data = JSON.print(self._data_as_json).to_utf8()
			self._socket.set_dest_address(dest_address[0], dest_address[1])
			self._socket.put_packet(bin_data)
		else:
			print('attempted to send incoming packet.')

class HeartbeatPacket extends Packet:
	var _seconds_between_resends
	var _resend_countdown
	var _await_reply_countdown
	var _attempts_countdown
	var _awaiting_reply = false
	var _sent_once_already = false
	
	#goes to shit if if send_immediately=false and seconds_between_resends == null:
	func _init(sender_name, dest_name, _socket, address, type, data_as_json, 
				send_immediately=true, seconds_between_resends=null).(sender_name, dest_name, 
																	  _socket, address, true, type, 
																	  data_as_json):
		self._resend_countdown = seconds_between_resends
		self._seconds_between_resends = seconds_between_resends
		self._await_reply_countdown = seconds_to_await_reply
		self._attempts_countdown = attempts_before_expiration
		if send_immediately:
			send()
			self._awaiting_reply = true
			self._sent_once_already = true
			
	func seconds_tick():
		#Returns true if the packet has expired
		if _awaiting_reply:
			_await_reply_countdown -= 1
			if _await_reply_countdown <= 0:
				print("attempt failed")
				_attempts_countdown -= 1
				if _attempts_countdown > 0:
					print("attempting to resend type: " + type)
					_await_reply_countdown = seconds_to_await_reply
					send()
				else:
					print("packet expired")
					return true

		elif _seconds_between_resends != null or not _sent_once_already:
			_resend_countdown -= 1
			if _resend_countdown <= 0:
				print("sent type: " + type)
				send()
				reset_expiry()
				_awaiting_reply = true
				_sent_once_already = true
		return false

	func reset_expiry():
		_awaiting_reply = false
		_attempts_countdown = attempts_before_expiration
		_await_reply_countdown = seconds_to_await_reply
		_resend_countdown = _seconds_between_resends

class HeartBeatPacketContainer:
	var _packets = []
	
	func add(packet, replace_same_peer_and_type = true):
		if replace_same_peer_and_type:
			remove_all_of_peer_and_type(packet.dest_name, packet.type)
		_packets.push_back(packet)
	
	func remove_all_of_peer(peer_name):
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name:
				_packets.erase(packet)
	
	func remove_all_of_type(type):
		for packet in _packets.duplicate():
			if packet.type == type:
				_packets.erase(packet)
	
	func remove_all_of_peer_and_type(peer_name, type):
		"""remove all packets that match peer AND type"""
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name and packet.type == type:
				_packets.erase(packet)
	
	func remove_all_of_peer_and_type_with_key_value(peer_name, type, key, value):
		"""remove all packets that match peer AND type AND that have a key with value"""
		for packet in _packets.duplicate():
			if packet.dest_name == peer_name:
				if packet.type == type:
					var data = packet.get_copy_of_json_data()
					if data.has(key) and data[key] == value:
							_packets.erase(packet)
			
	func reset_expiry_for_all_of_peer(peer_name):
		for packet in _packets:
			if packet.dest_name == peer_name:
				packet.reset_expiry()
				
	func reset_expiry_for_all_of_type(type):
		for packet in _packets.duplicate():
			if packet.type == type:
				packet.reset_expiry()
	
	func reset_expiry_for_all_of_peer_and_type(peer_name, type):
		"""reset all packets that match peer AND type"""
		for packet in _packets:
			if packet.dest_name == peer_name and packet.type == type:
				packet.reset_expiry()
				
	func get_packets_array_copy():
		return _packets.duplicate()














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
	func _init(your_name, peer_name, password, socket, heartbeat_container, 
				global_address, local_address=null):
		self._your_name = your_name
		self._peer_name = peer_name
		self._password = password
		self._socket = socket
		self._heartbeat_container = heartbeat_container
		self._global_address = [global_address[0], int(global_address[1])]
		if local_address != null:
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
		return typeof(_use_global) == TYPE_BOOL
	
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
		var seconds_between_resends = null
		var send_immediately = true
		var g_data = {'used-global': true}
		_heartbeat_container.add(make_heartbeat_packet('address-inquiry', g_data, 
								 send_immediately, seconds_between_resends, global_address()))
		var l_data = {'used-global': false}
		_heartbeat_container.add(make_heartbeat_packet('address-inquiry', l_data, 
								 send_immediately, seconds_between_resends, local_address()))
		
	func send_reliable_message(message):
		"""true if message send attempted"""
		if not is_confirmed():
			return false
		var data = {
			'message': message,
			'message-id': self._get_unique_msg_id()
		}
		var send_immediately = true
		var packet = make_heartbeat_packet('reliable-peer-message', data, send_immediately) 
		var replace_others_of_peer_and_type = false
		_heartbeat_container.add(packet, replace_others_of_peer_and_type)
		return true
		
	func send_unreliable_message(message):
		"""true if message send attempted"""
		if not is_confirmed():
			return false
		make_packet('unreliable-peer-message', {'message': message}).send()
		return true

	func add_id_to_msg_history(msg_id):
		_ids_of_received_messaged.push_back(msg_id)
		if _ids_of_received_messaged.size() > 50:
			#there's actually no better way to do this yet... would prefer [-25:]
			var new_array = []
			for i in range(25, _ids_of_received_messaged.size()):
				new_array.push_back(_ids_of_received_messaged[i])
			_ids_of_received_messaged = new_array
	
	func msg_history_contains(msg_id):
		return _ids_of_received_messaged.has(msg_id)
	
	func make_packet(type, data, custom_address=null):
		data = _add_security_outgoing(type, data)
		var address = custom_address
		if address == null:
			address = address()
		return Packet.new(your_name(), name(), socket(), address, true, type, data)
		
	func make_heartbeat_packet(type, data, send_immediately=true, seconds_between_resends=null, 
							   custom_address=null):
		data = _add_security_outgoing(type, data)
		var address = custom_address
		if address == null:
			address = address()
		return HeartbeatPacket.new(your_name(), name(), socket(), address, type, data, 
									send_immediately, seconds_between_resends)
	
	func _get_unique_msg_id():
		var id = _sent_message_id_counter
		_sent_message_id_counter += 1
		#overflow
		if _sent_message_id_counter < 0:
			_sent_message_id_counter = 0
		return id
		
	func _get_sorted_joined_string_elements_from_array(array):
		var string_elements = []
		for element in array:
			if typeof(element) == TYPE_STRING:
				string_elements.push_back(element)
		string_elements.sort()
		var string_of_sorted_strings = ''
		for string_element in string_elements:
				string_of_sorted_strings += string_element
		return string_of_sorted_strings
		
	func _add_security_outgoing(type, data):
		data['type'] = type
		data['sender'] = your_name()
		data['intended-recipient'] = name()
		var copy_for_hashing = data.duplicate()
		copy_for_hashing['password'] = password()
		var jstring = _get_sorted_joined_string_elements_from_array(copy_for_hashing.keys())
		jstring += _get_sorted_joined_string_elements_from_array(copy_for_hashing.values())
		var hash_string =jstring.sha256_text()
		data['hash-string'] = hash_string
		return data
		
	func check_security_and_make_incoming_packet(jdata, sender_address):
		#check everything is there
		if is_confirmed() and sender_address != address():
			return null
		elif sender_address != local_address() and sender_address != global_address():
			return null
		if not jdata.has('type'):
			return null
		if not jdata.has('intended-recipient') or jdata['intended-recipient'] != your_name():
			return null
		if not jdata.has('hash-string'):
			return null
		
		#check hashes match
		var sender_hash = jdata['hash-string']
		jdata.erase('hash-string')
		var jdata_copy = jdata.duplicate()
		jdata_copy['password'] = password()
		var jstring = _get_sorted_joined_string_elements_from_array(jdata_copy.keys())
		jstring += _get_sorted_joined_string_elements_from_array(jdata_copy.values())
		var hash_string =jstring.sha256_text()
		if hash_string != sender_hash:
			return null
		
		#all good
		var is_outgoing = false
		return Packet.new(name(), your_name(), socket(), sender_address, is_outgoing, jdata['type'], jdata)





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