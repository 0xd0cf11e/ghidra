#The script is used to decode strings encrypted in Emotet's binary
#@author Suweera De Souza 0xd0cf11e@gmail.com
#@category Malware Analysis
#@keybinding
#@menupath
#@toolbar

"""
	This scripts decodes strings encrypted in Emotet's binary.
"""

import struct

print "Start Decoding!"

listing = currentProgram.getListing()
loc = 0x401b70 # decode function

# get all code references made to the function
refs = getReferencesTo(toAddr(loc))

# iterate through each callee and decrypt encoded string
for r in refs:

	callee = r.getFromAddress()
	inst = getInstructionAt(callee)
	print("Callee: %s" % callee)

	# The parameters passed to the decode function
	# are in registers ecx and edx
	# iterate through max 100 instructions
	# to search for the values moved to the register
	i = 0 # counter
	ecx = 0 # offset with data
	edx = 0 # xor key
	comm = 0 # offset to comment on
	while((i < 100) and ((ecx == 0) or (edx == 0))):
		inst = getInstructionBefore(inst)
		if "MOV ECX" in inst.toString():
			comm = inst.getAddress()
			ecx = inst.getAddress(1)
			print("ECX = %s" % ecx)
		if "MOV EDX" in inst.toString():
			edx = getInt(inst.getAddress().add(1))
			print("EDX = %s" % edx)
		i += 1

	# xor to get string and comment
	if((ecx != 0) and (edx != 0)):
		size = getInt(ecx) ^ edx # first xor'ed dw gives string length
		print("String Length: %d" % size)
		i = 0 # counter
		result = ''
		while(i < size):
			ecx = ecx.add(4)
			xor = getInt(ecx) ^ edx
			setInt(ecx,xor) # patch the bytes back
			result += struct.pack('<I',xor)
			i += 4
		print("String: %s" % result[:size])
		codeUnit = listing.getCodeUnitAt(comm)
		codeUnit.setComment(codeUnit.EOL_COMMENT,result[:size])
	else:
		print "No ECX or EDX found"
