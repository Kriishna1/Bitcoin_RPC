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
    """Compute Merkle root from list of txids (little-endian hex strings)."""
    if not txids:
        return "00" * 32
    hashes = [bytes.fromhex(txid) for txid in txids]  # Keep little-endian
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            new_hash = double_sha256(combined)
            new_hashes.append(new_hash)
        hashes = new_hashes
    return hashes[0].hex()  # Return as little-endian hex

# -----------------------------
# Coinbase Transaction
# -----------------------------
def create_coinbase_tx_with_commitment(commitment: bytes) -> (str, str, str):
    """Create segwit coinbase transaction with witness commitment."""
    version = int_to_little_endian(1, 4)
    marker = b'\x00'
    flag = b'\x01'
    
    # Inputs
    tx_in_count = varint(1)
    prev_txid = b'\x00' * 32
    prev_index = int_to_little_endian(0xffffffff, 4)
    coinbase_data = b'abcd'
    script = varint(len(coinbase_data)) + coinbase_data
    sequence = int_to_little_endian(0xffffffff, 4)
    tx_in = prev_txid + prev_index + script + sequence

    # Outputs
    tx_out_count = varint(2)
    # Output 1: 50 BTC reward
    value1 = int_to_little_endian(5000000000, 8)
    script1 = varint(1) + b'\x51'  # OP_1
    tx_out1 = value1 + script1
    # Output 2: Witness commitment
    value2 = int_to_little_endian(0, 8)
    script2 = b'\x6a\x24' + b'\xaa\x21\xa9\xed' + commitment
    tx_out2 = value2 + varint(len(script2)) + script2

    # Witness & Locktime
    witness = varint(1) + varint(32) + b'\x00' * 32
    locktime = int_to_little_endian(0, 4)

    # Serialize
    coinbase_full = (version + marker + flag + tx_in_count + tx_in +
                    tx_out_count + tx_out1 + tx_out2 + witness + locktime)
    coinbase_nonwitness = version + tx_in_count + tx_in + tx_out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(coinbase_nonwitness)[::-1].hex()  # Little-endian txid
    return coinbase_full.hex(), coinbase_nonwitness.hex(), coinbase_txid

# -----------------------------
# Main Execution
# -----------------------------
# Load mempool transactions
mempool_dir = 'mempool'
mempool_txids = [f.split('.')[0] for f in os.listdir(mempool_dir) if f.endswith('.json')]

# Process transactions
mempool_txs = []
for txid in mempool_txids:
    tx_path = os.path.join(mempool_dir, f"{txid}.json")
    if os.path.exists(tx_path):
        with open(tx_path, 'r') as f:
            tx = json.load(f)
            mempool_txs.append({
                "txid": txid,
                "weight": tx['weight'],
                "fee": tx['fee'],
                "hex": tx['hex']
            })

# Create initial coinbase transaction
coinbase_full, coinbase_nonwitness, coinbase_txid = create_coinbase_tx_with_commitment(b'\x00'*32)
coinbase_weight = (len(coinbase_nonwitness)//2 * 3) + (len(coinbase_full)//2)

# Select transactions
mempool_txs.sort(key=lambda x: x['fee']/x['weight'], reverse=True)
selected_txs = []
total_weight = coinbase_weight
for tx in mempool_txs:
    if total_weight + tx['weight'] > MAX_BLOCK_WEIGHT:
        break
    selected_txs.append(tx)
    total_weight += tx['weight']

# Calculate wtxids (coinbase first)
wtxids = ["00"*32]  # Coinbase wtxid is 32 zero bytes
for tx in selected_txs:
    wtxid = double_sha256(bytes.fromhex(tx['hex']))[::-1].hex()  # Little-endian
    wtxids.append(wtxid)

# Witness commitment calculation
witness_root = compute_merkle_root(wtxids)
witness_reserved = bytes.fromhex("00"*32)
witness_commitment = double_sha256(bytes.fromhex(witness_root) + witness_reserved)

# Finalize coinbase transaction
coinbase_full, _, coinbase_txid = create_coinbase_tx_with_commitment(witness_commitment)

# Build block header
all_txids = [coinbase_txid] + [tx['txid'] for tx in selected_txs]
merkle_root = compute_merkle_root(all_txids)
header = b''
header += int_to_little_endian(0x20000000, 4)  # Version
header += bytes.fromhex("0000aaaa00000000000000000000000000000000000000000000000000000000")[::-1]  # Prev hash
header += bytes.fromhex(merkle_root)  # Merkle root
header += int_to_little_endian(int(time.time()), 4)  # Timestamp
header += int_to_little_endian(0x1f00ffff, 4)  # Bits

# Mine block
nonce = 0
target = 0x0000ffff << 208  # Difficulty target
while nonce <= 0xffffffff:
    header_with_nonce = header + int_to_little_endian(nonce, 4)
    block_hash = double_sha256(header_with_nonce)
    if int.from_bytes(block_hash[::-1], 'big') < target:
        break
    nonce += 1

# Write output
with open("out.txt", "w") as f:
    f.write(header_with_nonce.hex() + "\n")
    f.write(coinbase_full + "\n")
    f.write(coinbase_txid + "\n")
    for tx in selected_txs:
        f.write(tx['txid'] + "\n")