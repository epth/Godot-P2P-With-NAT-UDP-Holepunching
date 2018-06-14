extends Panel

onready var _output = find_node("Output", true)

func _ready():
	out("hello")
	out("my name is Daniel")



func out(message):
	self._output.text += message + '\n'
