#Get API name associated with hash and label the offsets the API call would be resolved at
#@author Suweera De Souza
#@category Malware Analysis
#@keybinding
#@menupath
#@toolbar

"""
    This script labels offsets with the API name where the API address would be resolved at.

    The user is asked for 2 inputs:
    - Offset where "CALL FUN_401230" is made (FUN_401230 matches API name to its hash)
    - File which has a list of API names (the export functions of the DLL that the current function is resolving)

"""

from java.lang import IllegalArgumentException

def getHashes(address,numHashes):
    """Method getting hashes that are pushed into stack

        Args:
            address (Address): Function offset from where to get hashes
            numHashes (int): number of hashes to extract

        Return:
            list: a list of hashes
    """
	hashList = []
	inst = getInstructionAt(address)
	i = 0
	while i < numHashes:
		opcode = inst.toString()
		if "MOV dword ptr " in opcode:
			hashList.append(opcode.split(',')[1])
			i += 1
		inst = getInstructionAfter(inst)
	return hashList

def hashXor(api_list,xor):
    """Emotet's hash-xor algorithm

        Args:
            api_list (list): list of API names
            xor (int): DWORD used to xor

        Return:
            dict: a dictionary of api name to its hash

    """
	result = {}
	for api in api_list:
		ecx = 0
		for _ in api:
			ecx  = (ecx * 0x1003f) & 0xffffffff
			ecx =  (ecx + ord(c)) & 0xffffffff
        	ecx = (ecx ^ xor) & 0xffffffff
        	result.update({hex(ecx)[:10]:api})
	return result


try:

	address = askAddress("Offset","Enter offset pointing to \"Call FUN_401230\" :")
	inst = getInstructionAt(address)

	if inst.toString() == "CALL 0x00401230":

		name = askFile("File with exported API names of DLL","Choose File:")
		f = open(str(name),'r')
		api_list = f.read().split()
		f.close()

		# Get the 3 arguments pushed to 0x401230's stackframe
		params = []
		print "Parameters pushed:"
		while len(params) < 3 :
			inst = getInstructionBefore(inst)
			if "PUSH" in inst.toString():
				addr = inst.getAddress()
				if getByte(addr) == 0x68:
					params.append(getInt(addr.add(1)))
				else:
					params.append(getByte(addr.add(1)))
				print inst.toString()

		listing = currentProgram.getListing()
		func = listing.getFunctionContaining(address).getEntryPoint()

		print "Getting hashes from " + func.toString()
		hash_stack = getHashes(func,params[0])
		hash_dict = hashXor(api_list,params[1])

		for h in range(len(hash_stack)):
			if hash_stack[h] in hash_dict:
				createLabel(toAddr((4*h)+params[2]),hash_dict[hash_stack[h]],False)
				print("%s : %s" % (hex((4*h)+params[2]), hash_dict[hash_stack[h]]))

	else:
		popup("Offset doesn't point to \"Call FUN_401230\"")

except IllegalArgumentException as error:
    Msg.warn(self, "Error during processing: " + error.toString())
