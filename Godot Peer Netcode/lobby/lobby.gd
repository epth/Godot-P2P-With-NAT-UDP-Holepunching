extends VBoxContainer

# class member variables go here, for example:
# var a = 2
# var b = "textvar"

func _ready():
	out("playing as: " + holepunch.get_user_name())
	holepunch.connect('packet_received', self, '_packet_received')

func out(message):
	"""prints a message to the gui console"""
	$Panel/VBoxContainer/MarginContainer/Output.add_text(message)
	$Panel/VBoxContainer/MarginContainer/Output.newline()


func _packet_received(packet):
	out("packet received in lobby: " + packet['type'] + " from " + packet['sender'])