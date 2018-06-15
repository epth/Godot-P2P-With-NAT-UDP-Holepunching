extends Panel

#get a handle to all these elements
onready var _handshake_ip_field = find_node("HandshakeServerIPField")
onready var _handshake_port_field = find_node("HandshakeServerPortField")
onready var _local_ip_field = find_node("LocalIPField")
onready var _local_port_field = find_node("LocalPortField")
onready var _join_username_field = find_node("JoinUserNameField")
onready var _register_servername_field = find_node("RegisterServerNameField")
onready var _join_servername_field = find_node("JoinServerNameField")
onready var _register_server_button = find_node("RegisterServerButton")
onready var _join_server_button = find_node("JoinServerButton")
onready var _peer_message_field = find_node("PeerMessageField")
onready var _peer_username_field = find_node("PeerUserNameField")
onready var _send_message_button = find_node("SendMessageButton")
onready var _print_peers_button = find_node("PrintPeersButton")
onready var _output_field = find_node("Output", true)

#create some wide-scope variables
var confirmed_peers = {}
var unconfirmed_peers = {}
var heartbeat_packets = HeartBeatPacketContainer.new()
var handshake_server_socket = null
var seconds_ticker = 0
var i_am_server = null
#keep null to differentiate between it and other peers
const SERVER_NAME = null


func _ready():
	#connect button-press signals
	_send_message_button.connect('pressed', self, '_send_message_to_peer')
	_print_peers_button.connect('pressed', self, '_print_peers')
	_register_server_button.connect('pressed', self, '_register_server')
	_join_server_button.connect('pressed', self, '_join_server')
	
	#defaults
	_handshake_ip_field.text = '35.197.160.85'
	_handshake_port_field.text = '5160'
	_local_ip_field.text = '192.168.1.127'
	_local_port_field.text = '3334'


func _process(delta):
	seconds_ticker += delta
	if seconds_ticker > 1:
		#code in here happens once a second
		seconds_ticker = 0
		for packet in heartbeat_packets.get_packets_array_copy():
			var packet_expired = packet.seconds_tick()
			if packet_expired:
				#non-servers should just give up
				if not i_am_server:
					give_up()
				#servers should give up if they were trying to register
				#otherwise it may just be that peer, so boot them
				else:
					if packet.type == 'registering-server':
						give_up()
					else:
						heartbeat_packets.remove_peer(packet.peer_name)
						#todo: remove matching unconfirmed peers
						#todo: remove confirmed matching peers
	
	#process messages from server
	if 	handshake_server_socket:
		while handshake_server_socket.get_available_packet_count() > 0:
			out("message received from server") 
			var jData = get_var_from_bytes(handshake_server_socket.get_packet())
			if jData['type'] == 'confirming-registration':
				heartbeat_packets.reset_expiry(SERVER_NAME, 'registering-server')
			elif jData['type'] == 'providing-peer-handshake-info':
				pass




func give_up():
	"""Resets everything, assuming we lost the connection completely"""
	out("given up")
	_join_server_button.disabled = false
	_register_server_button.disabled = false
	heartbeat_packets.clear()
	handshake_server_socket = null


func init():
	"""
	Depending on whether i_am_server, either register as a server
	or request to join a registered server
	"""
	#check required fields are present
	var fields_to_check = [_handshake_ip_field, _handshake_port_field,
						   _local_ip_field, _local_port_field]
	if i_am_server:
		fields_to_check.push_back(_register_servername_field)
	else:
		fields_to_check.push_back(_join_username_field)
		fields_to_check.push_back(_join_servername_field)
	for field in fields_to_check:
		if field.text.empty():
			out("field missing: " + field)
			return
	#initialise server socket (returns false on error)
	if not _init_server_socket():
		return
	#create first data packet
	var data = {
		'local-ip': _local_ip_field.text,
		'local-port': int(_local_port_field.text)
	}
	var type
	if i_am_server:
		type = 'registering-server'
		data['user-name'] = _register_servername_field.text
		data['seconds-before-expiry'] = 60
	else:
		type = 'requesting-to-join-server'
		data['user-name'] =  _join_username_field.text
		data['server-name'] = _join_servername_field.text
	#packet will be sent immediately, and every 15 seconds
	#the connection with the server will be closed for nonservers when they get a reply
	heartbeat_packets.add(HeartbeatPacket.new(SERVER_NAME, handshake_server_socket, 
											  type, data, 15, true))
	#update gui
	_join_server_button.disabled = true
	_register_server_button.disabled = true
	out("message sent to server of type: " + type)
	





func _init_server_socket():
	"""start listening to handshake server. Returns false if init fails"""
	#start listening
	handshake_server_socket = PacketPeerUDP.new()
	if handshake_server_socket.listen(int(_local_port_field.text)) != OK:
		out("invalid local port")
		return false
	#set address for sending packets
	handshake_server_socket.set_dest_address(_handshake_ip_field.text, 
 											 int(_handshake_port_field.text))
	return true


#############################################################
#############################################################
#                     BUTTON CONNECTORS                     #
#############################################################
func _register_server():
	i_am_server = true
	#sends registration packet
	init()

func _join_server():
	i_am_server = false
	#sends request to join
	init()


func _send_message_to_peer():
	pass

func _print_peers():
	out("blah")

#############################################################
#############################################################
#                     UTILITY FUNCTIONS                     #
#############################################################
func out(message):
	"""prints a message to the gui console"""
	_output_field.text += message + '\n'
	#set scroll to end
	_output_field.cursor_set_line(_output_field.get_line_count(), true)

func get_var_from_bytes(array_bytes):
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
	var udp_socket_instance #PacketPeerUDP instance
	var data_as_json
	var type #e.g. 'registering-server'
	
	func _init(peer_name, udp_socket_instance, type, data_as_json):
		"""adds the type to the data to be sent"""
		self.peer_name = peer_name
		self.udp_socket_instance = udp_socket_instance
		self.data_as_json = data_as_json
		self.data_as_json['type'] = type
		self.type = type
	func send():
		var bin_data = JSON.print(self.data_as_json).to_utf8()
		self.udp_socket_instance.put_packet(bin_data)

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
	func _init(peer_name, udp_socket_instance, type, data_as_json, 
				seconds_between_resends, send_immediately=false, 
				seconds_to_await_reply=1,
				attempts_before_expiration=3).(peer_name, 
				udp_socket_instance, type, data_as_json):
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
		print("expiry reset")
		_awaiting_reply = false
		_attempts_countdown = _attempts_before_expiration
		_await_reply_countdown = _seconds_to_await_reply
		_resend_countdown = _seconds_between_resends

class HeartBeatPacketContainer:
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