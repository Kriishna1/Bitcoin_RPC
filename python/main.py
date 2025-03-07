import os
import json
import time
import hashlib

MAX_BLOCK_WEIGHT = 4000000

# -----------------------------
# Helper functions
# -----------------------------
def double_sha256(data: bytes) -> bytes:
    """Compute double SHA256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def int_to_little_endian(value: int, length: int) -> bytes:
    """Convert an integer to little-endian bytes of given length."""
    return value.to_bytes(length, byteorder='little')

def varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin varint."""
    if n < 0xfd:
        return n.to_bytes(1, 'little')
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')

def compute_merkle_root(txids: list) -> str:
    """
    Compute the Merkle root from a list of txids (hex strings).
    """
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i+1]))
        hashes = new_hashes
    return hashes[0][::-1].hex()

def create_coinbase_tx_with_commitment(commitment: bytes) -> (str, str, str):
    """Create a segwit coinbase transaction with a witness commitment."""
    version = int_to_little_endian(1, 4)
    marker = b'\x00'
    flag = b'\x01'
    tx_in_count = varint(1)
    prev_txid = b'\x00' * 32
    prev_index = (0xffffffff).to_bytes(4, 'little')
    coinbase_data = b'abcd'
    coinbase_script = varint(len(coinbase_data)) + coinbase_data
    sequence = (0xffffffff).to_bytes(4, 'little')
    tx_in = prev_txid + prev_index + coinbase_script + sequence
    tx_out_count = varint(2)
    reward = (5000000000).to_bytes(8, 'little')
    script1 = varint(1) + b'\x51'
    tx_out1 = reward + script1
    value2 = (0).to_bytes(8, 'little')
    prefix = bytes.fromhex("aa21a9ed")
    script2 = b'\x6a' + b'\x24' + prefix + commitment
    tx_out2 = value2 + varint(len(script2)) + script2
    locktime = (0).to_bytes(4, 'little')
    witness = varint(1) + varint(32) + (b'\x00' * 32)
    coinbase_tx_full = (version + marker + flag + tx_in_count + tx_in + tx_out_count + tx_out1 + tx_out2 + witness + locktime)
    coinbase_tx_nonwitness = version + tx_in_count + tx_in + tx_out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(coinbase_tx_nonwitness)[::-1].hex()
    return coinbase_tx_full.hex(), coinbase_tx_nonwitness.hex(), coinbase_txid

mempool_dir = 'mempool'
mempool_txids = []
for filename in os.listdir(mempool_dir):
    if filename.endswith('.json'):
        filepath = os.path.join(mempool_dir, filename)
        with open(filepath, 'r') as f:
            tx = json.load(f)
            if 'txid' in tx and 'hex' in tx:
                mempool_txids.append(tx['txid'])

coinbase_full, coinbase_nonwitness, coinbase_txid = create_coinbase_tx_with_commitment(b'\x00'*32)
total_weight = len(coinbase_full) // 2
tx_data = {}
for txid in mempool_txids:
    with open(os.path.join(mempool_dir, f"{txid}.json"), 'r') as f:
        tx_json = json.load(f)
        tx_data[txid] = tx_json
wtxids = ["00" * 32]
selected_mempool_txids = []
for txid, tx in tx_data.items():
    wtxid = double_sha256(bytes.fromhex(tx['hex']))[::-1].hex()
    wtxids.append(wtxid)
    selected_mempool_txids.append(txid)
witness_merkle_root = compute_merkle_root(wtxids)
witness_commitment = double_sha256(bytes.fromhex(witness_merkle_root + "00" * 32))
coinbase_full, _, coinbase_txid = create_coinbase_tx_with_commitment(witness_commitment)
block_version = int_to_little_endian(0x20000000, 4)
prev_block_hash = bytes.fromhex("0000aaaa" + "00" * 28)[::-1]
merkle_root_tx = compute_merkle_root([coinbase_txid] + selected_mempool_txids)
merkle_root_bytes = bytes.fromhex(merkle_root_tx)[::-1]
timestamp = int_to_little_endian(int(time.time()), 4)
bits = int_to_little_endian(0x1f00ffff, 4)
nonce = 0
difficulty_target = int("0000ffff" + "00" * 28, 16)
while True:
    nonce_bytes = int_to_little_endian(nonce, 4)
    header = block_version + prev_block_hash + merkle_root_bytes + timestamp + bits + nonce_bytes
    header_hash = double_sha256(header)
    if int.from_bytes(header_hash[::-1], 'big') < difficulty_target:
        break
    nonce += 1
block_header_hex = header.hex()
with open("out.txt", "w") as f:
    f.write(block_header_hex + "\n")
    f.write(coinbase_full + "\n")
    f.write(coinbase_txid + "\n")
    for txid in selected_mempool_txids:
        f.write(txid + "\n")
print("Block mined and out.txt generated successfully.")
