import Levenshtein
from hashlib import sha1

dht = []


def create_hash(text):
    hash_obj = sha1(str.encode(text))
    hashed = hash_obj.hexdigest()
    return hashed


def get_similarity(data_hash):
    similarities = {}

    for node in dht:
        if '-' not in node:
            continue

        node = node.replace('\n', '')
        node_address = node.split('-')[1]
        node_hash = node.split('-')[0]
        similarity = Levenshtein.ratio(str(data_hash), node_hash)
        print("Similarity " + str(data_hash) + " and " + node_hash + '-' + node_address + " is " + str(similarity))
        similarities[node_address] = [similarity, node_hash]

    sorted_similarities = sorted(similarities.items(), key=lambda x: x[1], reverse=True)  # Sort in descending order
    return sorted_similarities
