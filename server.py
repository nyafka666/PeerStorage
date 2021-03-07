import socket
import threading
import pickle
from hashlib import sha1
import Levenshtein
import os
import tools

dht_path = ''
dht = []


def connection(conn, addr):
    while True:
        data = conn.recv(1024)
        if not data:
            conn.close()
            break

        data = data.decode(encoding='utf-8')
        # The line below retrieves the first part of the received command,
        # which placed before ':' to determine whether this request is a 'put' or 'get'.
        cmd = data.split(':')[0]
        print(cmd)
        print(data)
        address = data.split(':')[1]  # Get sender's "hash-127.0.0.1" from received data
        ip = address.split('-')[1]  # We removed "hash-" from the address to get sender's ip
        port = data.split(':')[2]  # Get sender's port by splitting string
        dht_append(address + ':' + port)

        if cmd == 'get':
            print("GET request!")
            conn.sendall(pickle.dumps(tools.dht))
        elif cmd == 'put':  # Example of put command: put:hash-127.0.0.1:33:file.txt=some_text
            put_content = str(data).split(':')[3]  # Get the last part of put request (file.txt=some_text)
            sender_address = ip + ':' + port
            file_name = put_content.split('=')[0]
            file_content = put_content.split('=')[1]
            file_hash = create_hash(file_name)
            file_hash_path = dht_path.split('.')[0] + '/' + file_hash  # Path to %file_hash%
            
            if '<<search>>' in file_content and os.path.isfile(file_hash_path):
                # If the file content is '<<search>>', we must find it
                with open(file_hash_path, 'r') as f:
                    result = f.read()
            else:
                # And if we couldn't find the requested file, then we
                # use "put_handler" function to find out which nodes can have it.
                # This function is also used to save files from 'put' request and
                # send nodes that are "closer" to the file hash.
                result = put_handler(file_hash, sender_address.replace('\n', ''), file_content, file_hash_path)
            conn.sendall(pickle.dumps(result))
        else:
            conn.sendall(pickle.dumps("[wrong_command]"))
        print(str(data))
        conn.close()
        break


def put_handler(file_hash, sender_ip, file_content, file_hash_path):
    result = '[OK]'
    print(tools.dht)
    hash_id = tools.dht[0].split('-')[0]
    print(hash_id)

    sorted_similarities = tools.get_similarity(file_hash)
    sorted_similarities = dict(sorted_similarities)

    i = 0
    nodes_to_send = []
    for node in sorted_similarities.keys():
        if i > 1:  # i - number of nodes we want to include in the best similarity list
            break
        elif sender_ip in node:
            # If the node in current iteration is equal to
            # sender's ip, which is being processed by 'connection' function,
            # then we need to skip the iteration.
            print("Sender_ip: " + sender_ip + " Node: " + node)
            continue

        node_metadata = sorted_similarities[node]  # Get node's hash similarity with the file_hash
        node_hash = node_metadata[1]  # Get node's hash from the node_metadata
        # node_metadata is a list that contains [similarity, node_hash],
        # so we need to get the second element (node_hash) from it.

        if node_hash == hash_id and file_content != "<<search>>":
            # If our node is in the first N nodes in sorted_similarities, we
            # should to save it. The file name is equal to its hash name,
            # because if current request would be 'search', then we would have to find
            # the contents of the file by its hash.
            with open(file_hash_path, 'w') as f:
                f.write(file_content)
            print("File saved!")

        nodes_to_send.append(node)
        i += 1
    print("5 nodes to send: " + str(nodes_to_send))

    if len(nodes_to_send) != 0:
        result = nodes_to_send
    return result


def listening(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen()

    print("Server started on " + host + ':' + str(port))

    while True:
        conn, addr = sock.accept()
        print('Connected by', addr)
        conn_thread = threading.Thread(target=connection, args=(conn, addr,))
        conn_thread.start()


def dht_append(node):
    # This function checks if a node exists in our hash table,
    # and if not, we add new node to the hash table.
    print("Node to append is " + node)
    print(tools.dht)
    if node.replace('\n', '') not in str(tools.dht):
        if '\n' not in node:
            node += '\n'
        with open(dht_path, 'a') as f:
            f.write(node)
        with open(dht_path, 'r') as f:
            new_dht = f.readlines()
        tools.dht = new_dht


def create_hash(text):
    hash_obj = sha1(str.encode(text))
    hashed = hash_obj.hexdigest()
    return hashed


def start(host, port):

    with open(dht_path, 'r') as f:
        tools.dht = f.readlines()

    listen_thread = threading.Thread(target=listening, args=(host, int(port), ))
    listen_thread.start()


if __name__ == "__main__":
    print('Error')
