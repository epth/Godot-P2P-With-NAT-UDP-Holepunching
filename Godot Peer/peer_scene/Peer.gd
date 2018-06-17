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
onready var _get_server_list_button = find_node("GetServerListButton")
onready var _cut_handshake_button = find_node("CutConnectionWithHandshakeButton")
onready var _output_field = find_node("Output", true)

func _ready():
	#connect button-press signals
	_send_message_button.connect('pressed', self, '_send_message_to_peer')
	_print_peers_button.connect('pressed', self, '_print_peers')
	_register_server_button.connect('pressed', self, '_register_server')
	_join_server_button.connect('pressed', self, '_join_server')
	_get_server_list_button.connect('pressed', self, '_request_server_list')
	_cut_handshake_button.connect('pressed', self, '_cut_handshake')
	#connect P2P signals
	$HolePunch.connect('session_terminated', self, '_give_up')
	$HolePunch.connect('peer_dropped', self, '_peer_dropped')
	$HolePunch.connect('peer_confirmed', self, '_new_peer')
	$HolePunch.connect('packet_received', self, '_packet_received')
	$HolePunch.connect('received_unreliable_message_from_peer', self, '_message_from_peer')
	$HolePunch.connect('received_reliable_message_from_peer', self, '_message_from_peer')
	$HolePunch.connect('error', self, '_error')
	$HolePunch.connect('received_server_list', self, '_print_server_list')
	#defaults
	_handshake_ip_field.text = '35.197.160.85'
	_handshake_port_field.text = '5160'
	_local_ip_field.text = '192.168.1.127'
	_local_port_field.text = '3334'


func _cut_handshake():
	$HolePunch.drop_connection_with_handshake_server()
	out("handshake cut: operating as full P2P")
	
func _request_server_list():
	
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	out("request for servers sent to " + handshake_ip)
	$HolePunch.request_server_list([handshake_ip, handshake_port])

func _print_server_list(info):
	out("received server list from " + info['server-address'][0])
	for server in info['server-list']:
		out("    " +server)


func _error(message):
	out("error: " + message)

func _give_up():
	out("Connection terminated.")
	_join_server_button.disabled = false
	_register_server_button.disabled = false

func _peer_dropped(peer_name):
	out("Peer dropped: " + peer_name)

func _new_peer(info):
	out("New peer:")
	out("    " + info['name'] + " at " + str(info['address']))

func _packet_received(jData):
	out("packet received of type: " + jData['type'])
	
func _message_from_peer(jData):
	out("message from " + jData['sender'])
	out("   " + str(jData['message']))

func _send_message_to_peer():
	$HolePunch.send_reliable_message_to_peer(_peer_username_field.text, _peer_message_field.text)

func _register_server():
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	var local_ip = _local_ip_field.text
	var local_port = int(_local_port_field.text)
	var server_name = _register_servername_field.text
	$HolePunch.init_server(handshake_ip, handshake_port, local_ip, local_port, server_name)

func _join_server():
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	var local_ip = _local_ip_field.text
	var local_port = int(_local_port_field.text)
	var server_name = _join_servername_field.text
	var user_name = _join_username_field.text
	$HolePunch.init_client(handshake_ip, handshake_port, local_ip, local_port, user_name, server_name) 


func _print_peers():
	out("connected peers:")
	for peer in $HolePunch.get_peers():
		out("    " + str(peer))

func out(message):
	"""prints a message to the gui console"""
	_output_field.add_text(message)
	_output_field.newline()
