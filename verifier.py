import socket
import math
import random
import time
from datetime import datetime

delay = 0
BUFFER_SIZE = 1024 # send 4096 bytes each time step

#Verifier's local address
VERIFIER_HOST = "127.0.0.1"
VERIFIER_PORT = 8001
print("Verifier's local address:\nhost: {}     port: {}\n".format(VERIFIER_HOST, VERIFIER_PORT))

key = input("Enter the shared key: "); print()

# Initialising socket interface at verifier side
s = socket.socket()	
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# Associating the socket with Verifier's local address
s.bind((VERIFIER_HOST, VERIFIER_PORT))
# Enabling the verifier to accept connections
s.listen(5)
print(f"Listening as {VERIFIER_HOST}:{VERIFIER_PORT}")
# Verifier accepting a connection
claimant_socket, address = s.accept() 
print(f"Claimant: {address} is connected.\n")



# Encrypting Function (using Columnar Transposition)
def encrypt(msg, key):
	cipher = ""
	# track key indices
	k_indx = 0

	msg_len = float(len(msg))
	msg_lst = list(msg)
	key_lst = sorted(list(key))

	# calculate column of the matrix
	col = len(key)
	# calculate maximum row of the matrix
	row = int(math.ceil(msg_len / col))

	# add the padding character '_' in empty
	# the empty cell of the matix
	fill_null = int((row * col) - msg_len)
	msg_lst.extend('_' * fill_null)

	# create Matrix and insert message and
	# padding characters row-wise
	matrix = [msg_lst[i: i + col]
			for i in range(0, len(msg_lst), col)]

	# read matrix column-wise using key
	for _ in range(col):
		curr_idx = key.index(key_lst[k_indx])
		cipher += ''.join([row[curr_idx]
						for row in matrix])
		k_indx += 1

	return cipher
	

# Decrypting Function (using Columnar Transposition)
def decrypt(cipher, key):
	msg = ""

	# track key indices
	k_indx = 0

	# track msg indices
	msg_indx = 0
	msg_len = float(len(cipher))
	msg_lst = list(cipher)

	# calculate column of the matrix
	col = len(key)
	
	# calculate maximum row of the matrix
	row = int(math.ceil(msg_len / col))

	# convert key into list and sort
	# alphabetically so we can access
	# each character by its alphabetical position.
	key_lst = sorted(list(key))

	# create an empty matrix to
	# store deciphered message
	dec_cipher = []
	for _ in range(row):
		dec_cipher += [[None] * col]

	# Arrange the matrix column wise according
	# to permutation order by adding into new matrix
	for _ in range(col):
		curr_idx = key.index(key_lst[k_indx])

		for j in range(row):
			dec_cipher[j][curr_idx] = msg_lst[msg_indx]
			msg_indx += 1
		k_indx += 1

	# convert decrypted msg matrix into a string
	try:
		msg = ''.join(sum(dec_cipher, []))
	except TypeError:
		raise TypeError("This program cannot",
						"handle repeating words.")

	null_count = msg.count('_')

	if null_count > 0:
		return msg[: -null_count]

	return msg


def claimant_to_verifier_auth(key):
    #verifier receiving challenge
    nonce = claimant_socket.recv(BUFFER_SIZE).decode()
    time.sleep(delay)
    print("Challenge from claimant: "+str(nonce))

    # Encrypting the nonce using the shared key
    response = encrypt(nonce,key)
    time.sleep(delay)
    print("encrypting...")
    time.sleep(delay)
    print("Response to claimant :", response)

    #verifier sending response
    claimant_socket.send(response.encode())

    # Result of Claimant to Verifier authentication sent by claimant
    message = claimant_socket.recv(BUFFER_SIZE).decode()
    print(message); print()
    

def verifier_to_claimant_auth(method, key):
    
    challenge = 0 #declaration

    if method == 1 or method == 3:
        # Generating nonce
        size = random.randint(10,50)
        challenge = ''.join(random.choices("0123456789", k = size))
        time.sleep(delay)
        print("Generated nonce: "+challenge)
    elif method == 2:
        # Generating Timestamp
        now = datetime.now()
        challenge = now.strftime("%H%M%S")
        time.sleep(delay)
        print("Generated timestamp: "+challenge)
    
    #Sending challenge to claimant as requested
    claimant_socket.send(challenge.encode())

    #receiving response
    response = claimant_socket.recv(BUFFER_SIZE).decode()
    time.sleep(delay)
    print("response received: "+ response)

    # decrypting response using shared key
    time.sleep(delay)
    print("decrypting the response...")
    decrypted_response = decrypt(response, key)
    time.sleep(delay)
    print("decrypted response: "+decrypted_response)

    # comparing decrypted_response and challenge
    if decrypted_response == challenge:
        time.sleep(delay)
        claimant_socket.send("You are authenticated".encode())
        print("Authenticated"); print()
        if method == 3:
            claimant_to_verifier_auth(key)
    else:
        time.sleep(delay)
        claimant_socket.send("You are not authenticated".encode())
        print("Authentication Failed"); print()




while True:
    # Verifier gets challenge request from claimant
    message = claimant_socket.recv(BUFFER_SIZE).decode()
    time.sleep(delay)
    print("received challenge request")

    if message[:22]=="Authentication Request":
        method = int(message[-1])
        verifier_to_claimant_auth(method, key)