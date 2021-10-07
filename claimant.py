import socket
import math
import random
import time

delay = 0
BUFFER_SIZE = 1024 # send 4096 bytes each time step

# verifier's local address
host = '127.0.0.1' 
port = 8001
#Claimant's local address
CLAIMANT_HOST = "127.0.0.1"
CLAIMANT_PORT = 8008
print("Claimant's local address:\nhost: {}     port: {}\n".format(CLAIMANT_HOST, CLAIMANT_PORT))

key = input("Enter the shared key: "); print()

# Initialising socket interface at claimant side
s = socket.socket()
# Associating the socket with claimant's local address
s.bind((CLAIMANT_HOST, CLAIMANT_PORT))
print(f"Connecting to Verifier: {host}:{port}")
s.connect((host, port))
print("Connected.\n")

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
    


def Authentication(method,key):
    # Claimant wants to be challenged by Verifier
    print("sending challenge request...")
    s.send(("Authentication Request - "+str(method)).encode())

    # Claimant receiving challenge
    challenge = s.recv(BUFFER_SIZE).decode()
    time.sleep(delay)
    print("Received challenge: "+str(challenge))

    # Claimant encrypting the challenge using the shared key
    response = encrypt(challenge, key)
    time.sleep(delay)
    print("encrypting...")
    time.sleep(delay)
    print("Response :", response)

    #claimant sending response
    s.send(response.encode())

    # claimant gets to know if he/she is authenticated
    message = s.recv(BUFFER_SIZE).decode()
    print(message)

    if message == "You are authenticated" and method == 3:
        time.sleep(delay)
        print("Undergoing Claimant to Verifier Authentication...")

        # Generating nonce
        size = random.randint(10,50)
        nonce = ''.join(random.choices("0123456789", k = size))
        time.sleep(delay)
        print("Generated Nonce: "+ str(nonce))

        # Claimant sends the challenge
        s.send(nonce.encode())  

        # Claimant receives response
        response = s.recv(BUFFER_SIZE).decode()
        time.sleep(delay)
        print("response received: "+ response)

        # decrypting response using shared key
        time.sleep(delay)
        print("decrypting the response...")
        decrypted_response = decrypt(response, key)
        time.sleep(delay)
        print("decrypted response: "+decrypted_response)

        if decrypted_response == nonce:
            time.sleep(delay)
            print("Two Way Authenticated");print()
            s.send("Two Way Authenticated".encode())
        else:
            time.sleep(delay)
            print("Claimant to Verifier Authentication Failed");print()
            s.send("Claimant to Verifier Authentication Failed".encode())
    else:
        print()



# Input shared key
while True: 
    method = int(input("1. Authentication using Nonce, 2. Authentication using Time-Stamp , 3. Bidirectional Authentication\n"))
    if method not in [1,2,3]:
        continue
    Authentication(method,key)