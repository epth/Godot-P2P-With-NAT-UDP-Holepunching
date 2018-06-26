extends Node


const SERVER_ID = 1
const MAX_PLAYERS = 4
const COMPRESSION_MODE = NetworkedMultiplayerENet.COMPRESS_ZLIB
var me_as_peer = null #will hold the NetworkedMultiplayerENet
var my_info = {}

signal high_level_msg_received

func _ready():
	get_tree().connect('network_peer_disconnected', self, '_player_disconnected')
	get_tree().connect('connected_to_server', self, '_connected_ok')
	get_tree().connect('server_disconnected', self, '_server_disconnected')



###########################################
###########################################
#####          CREATION               #####
###########################################

func create_server(address, player_info):
	player_info.id = SERVER_ID
	global.player_infos = {}
	global.player_infos[player_info.name] = player_info
	my_info = player_info
	me_as_peer = NetworkedMultiplayerENet.new()
	me_as_peer.set_compression_mode(COMPRESSION_MODE)
	me_as_peer.create_server(address[1], MAX_PLAYERS)
	get_tree().set_network_peer(me_as_peer)
	return true

func join_server(server_address, player_info):
	me_as_peer = NetworkedMultiplayerENet.new()
	me_as_peer.set_compression_mode(COMPRESSION_MODE)
	me_as_peer.create_client(server_address[0], server_address[1])
	get_tree().set_network_peer(me_as_peer)
	player_info.id = get_tree().get_network_unique_id()
	my_info = player_info
	return true

func _connected_ok():
	rpc("_register_player", my_info)

remote func _register_player(player_info):
	global.player_infos[player_info.name] = player_info
	if get_tree().is_network_server():
		#fill in the new guy about other players
		for other_info in global.player_infos.values():
			rpc_id(player_info.id, "_register_player", other_info)
	#global.lobby_update_pending = true



###########################################
###########################################
#####          UPDATING               #####
###########################################


#func propagate_player_info():
#	var my_id = get_tree().get_network_unique_id()
#	rpc("_update_player_info", my_id, global.player_infos[my_id])
#
#remote func _update_player_info(id, player_info):
#	global.player_infos[id] = player_info
#	global.lobby_update_pending = true
#
#func propagate_settings():
#	rpc("_update_settings", global.settings)
#
#remote func _update_settings(settings):
#	#global.settings = settings
#	#global.lobby_update_pending = true
#	pass


###########################################
###########################################
#####          MESSAGES               #####
###########################################
remote func receive_message(message):
	emit_signal('high_level_msg_received', message)

func send_message(peer_name, message):
	print("sending message")
	rpc_id(global.player_infos[peer_name].id, "receive_message", message)


###########################################
###########################################
#####          QUITTING               #####
###########################################

func clear_connection():
	me_as_peer.close_connection()
	global.player_infos = {}

func _player_disconnected(id):
	global.player_infos.erase(id)
	global.lobby_update_pending = true

func _server_disconnected():
	clear_connection()
	global.goto_scene(global.landing_page_scene)
