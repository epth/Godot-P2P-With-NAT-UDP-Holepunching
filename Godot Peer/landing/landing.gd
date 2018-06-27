extends Panel
#get a handle to all these elements
onready var _handshake_ip_field = find_node("HandshakeServerIPField")
onready var _handshake_port_field = find_node("HandshakeServerPortField")
onready var _local_ip_field = find_node("LocalIPField")
onready var _local_port_field = find_node("LocalPortField")
onready var _username_field = find_node("UserNameField")
onready var _password_field = find_node("PasswordField")
onready var _server_field = find_node("ServerField")
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
	holepunch.connect('confirmed_as_server', self, '_confirmed_as_server')
	holepunch.connect('confirmed_as_client', self, '_confirmed_as_client')
	
	holepunch.connect('session_terminated', self, '_give_up')
	holepunch.connect('peer_dropped', self, '_peer_dropped')
	holepunch.connect('client_confirmed', self, '_new_peer')
	holepunch.connect('packet_received', self, '_packet_received')
	holepunch.connect('packet_blocked', self, '_packet_blocked')
	holepunch.connect('received_unreliable_message_from_peer', self, '_message_from_peer')
	holepunch.connect('received_reliable_message_from_peer', self, '_message_from_peer')
	holepunch.connect('error', self, '_error')
	holepunch.connect('received_server_list', self, '_print_server_list')
	
	holepunch.connect('peer_confirmed_reliable_message_received', self, '_peer_confirmed_message')
	holepunch.connect('reliable_message_timeout', self, '_reliable_message_timeout')
	holepunch.connect('peer_timeout', self, '_peer_check_timeout')
	holepunch.connect('peer_connection_failed', self, '_peer_handshake_timeout')
	holepunch.connect('packet_sent', self, '_packet_sent')
	holepunch.connect('peer_list_updated', self, '_peer_list_updated')
	#defaults
	_handshake_ip_field.text =  '127.0.0.1'# '35.197.160.85'
	_handshake_port_field.text = '5160'
	_local_ip_field.text = '192.168.1.127'
	_local_port_field.text = '3334'
	_username_field.text = 'euler'


func out(message):
	"""prints a message to the gui console"""
	_output_field.add_text(message)
	_output_field.newline()

func _peer_list_updated(peers):
	out("peer list updated:")
	for peer in peers:
		out("    " + peer)

func _packet_sent(data):
	out("packet sent of type: " + data['__type'] +" to " + data['__destination-name'])

func _packet_blocked(address):
	out("packet blocked from: " + str(address))

######################################
##           INPUTS
######################################
func _cut_handshake():
	holepunch.drop_connection_with_handshake_server()
	out("handshake cut: operating as full P2P")
	#global.goto_scene(global.lobby_scene)
	
func _request_server_list():
	var handshake_ip = _handshake_ip_field.text
	var handshake_port = int(_handshake_port_field.text)
	out("request for servers sent to " + handshake_ip)
	holepunch.request_server_list([handshake_ip, handshake_port])


func _send_message_to_peer():
	var to = _peer_username_field.text
	if to == "":
		to = null
	holepunch.send_reliable_message_to_peer(to, _peer_message_field.text)


func _register_server():
	var handshake_address = [_handshake_ip_field.text, int(_handshake_port_field.text)]
	var local_address = [_local_ip_field.text, int(_local_port_field.text)]
	var user_name = _username_field.text
	var password = _password_field.text
	if password == "":
		password == null
	holepunch.init_server(handshake_address, local_address, user_name, password)

func _join_server():
	var handshake_address = [_handshake_ip_field.text, int(_handshake_port_field.text)]
	var local_address = [_local_ip_field.text, int(_local_port_field.text)]
	var server_name = _server_field.text
	var user_name = _username_field.text
	var password = _password_field.text
	if password == "":
		password == null
	holepunch.init_client(handshake_address, local_address, user_name, server_name, password) 


func _print_peers():
	out("connected peers:")
	for peer in holepunch.get_peers():
		out("    " + peer)



######################################
##           SIGNALS
######################################


func _confirmed_as_server(server_address):
	out("confirmed as server")
	out("    server address: " + str(server_address))
	

func _confirmed_as_client(server_address):
	out("confirmed as client")
	out("    server address: " + str(server_address))

func _message_from_peer(data):
	out("message from " + data['from'] + ":")
	out("   " + str(data['message']))


func _peer_confirmed_message(data):
	out("peer confirmed message received: ")
	out("   " + str(data['message']))

func _reliable_message_timeout(data):
	out("reliable message timeod out: " + str(data['message']))


func _peer_check_timeout(peer_name):
	out("peer check timeout for peer: " + peer_name)
	
func _peer_handshake_timeout(peer_name):
	out("failed to connect to " + peer_name)
	
	
func _print_server_list(info):
	out("received server list from " + info['server-address'][0])
	out("servers: ")
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

func _packet_received(data):
	out("packet received of type: " + data['__type'])
	

