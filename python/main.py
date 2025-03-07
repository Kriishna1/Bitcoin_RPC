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
    Each txid is converted into little-endian bytes for hashing.
    Returns the final hash in big-endian hex.
    """
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]
    if len(hashes) == 0:
        return "00" * 32
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i+1]))
        hashes = new_hashes
    return hashes[0][::-1].hex()

# -----------------------------
# Create a Coinbase Transaction with a given Witness Commitment
# -----------------------------
def create_coinbase_tx_with_commitment(commitment: bytes) -> (str, str, str):
    """
    Create a segwit coinbase transaction using the provided witness commitment.
    The transaction includes:
      - 1 input (coinbase input with "abcd" as coinbase data)
      - 2 outputs:
           Output 1: Block reward (50 BTC) with a simple script (OP_1)
           Output 2: Witness commitment output with script:
                     OP_RETURN (0x6a) || OP_PUSH36 (0x24) || 0xaa21a9ed || commitment
      - Witness: one element of length 32 (32 zero bytes)
      - locktime = 0

    The coinbase txid is computed from the non-witness serialization.
    (Note: Although the canonical wTXID is computed as
           HASH256([version][marker][flag][inputs][outputs][witness][locktime]),
     per BIP141 the coinbase’s witness txid is defined to be 32 zero bytes.)
    
    Returns:
      - Full serialized coinbase transaction (hex, with witness)
      - Non-witness serialization (hex)
      - Coinbase txid (hex)
    """
    # Version (4 bytes)
    version = int_to_little_endian(1, 4)
    # Marker and flag for segwit
    marker = b'\x00'
    flag = b'\x01'
    # Input count: 1
    tx_in_count = varint(1)
    # Coinbase input: prev_txid = 32 zero bytes, index = 0xffffffff
    prev_txid = b'\x00' * 32
    prev_index = (0xffffffff).to_bytes(4, 'little')
    coinbase_data = b'abcd'
    coinbase_script = varint(len(coinbase_data)) + coinbase_data
    sequence = (0xffffffff).to_bytes(4, 'little')
    tx_in = prev_txid + prev_index + coinbase_script + sequence

    # Output count: 2
    tx_out_count = varint(2)
    # Output 1: Block reward output (50 BTC)
    reward = (5000000000).to_bytes(8, 'little')
    script1 = varint(1) + b'\x51'  # OP_1 is 0x51
    tx_out1 = reward + script1

    # Output 2: Witness commitment output: value = 0
    value2 = (0).to_bytes(8, 'little')
    # Build the witness commitment script:
    # It must have: OP_RETURN (0x6a) || OP_PUSH36 (0x24) || 0xaa21a9ed || commitment
    prefix = bytes.fromhex("aa21a9ed")
    script2 = b'\x6a' + b'\x24' + prefix + commitment
    tx_out2 = value2 + varint(len(script2)) + script2

    # Locktime (4 bytes)
    locktime = (0).to_bytes(4, 'little')
    # Witness: one element of length 32 (32 zero bytes)
    witness = varint(1) + varint(32) + (b'\x00' * 32)

    # Full coinbase serialization (with witness)
    coinbase_tx_full = (version + marker + flag + tx_in_count + tx_in +
                        tx_out_count + tx_out1 + tx_out2 + witness + locktime)
    # Non-witness serialization (for coinbase txid)
    coinbase_tx_nonwitness = version + tx_in_count + tx_in + tx_out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(coinbase_tx_nonwitness)[::-1].hex()
    return coinbase_tx_full.hex(), coinbase_tx_nonwitness.hex(), coinbase_txid

# -----------------------------
# Process Mempool Transactions
# -----------------------------
# Each mempool transaction JSON must be named "<txid>.json" and include a "hex" field.
mempool_dir = 'mempool'
mempool_txids = []
for filename in os.listdir(mempool_dir):
    if filename.endswith('.json'):
        filepath = os.path.join(mempool_dir, filename)
        try:
            with open(filepath, 'r') as f:
                tx = json.load(f)
                if 'txid' in tx and 'vin' in tx and 'vout' in tx and 'hex' in tx:
                    mempool_txids.append(tx['txid'])
        except Exception:
            continue

# -----------------------------
# Limit Mempool Transactions by Maximum Block Weight
# -----------------------------
# Calculate coinbase weight using Bitcoin weight formula:
# weight = (base size * 3) + total size
coinbase_full, coinbase_nonwitness, coinbase_txid = create_coinbase_tx_with_commitment(b'\x00'*32)
total_size = len(coinbase_full) // 2      # full size in bytes
base_size = len(coinbase_nonwitness) // 2    # non-witness size in bytes
coinbase_weight = base_size * 3 + total_size

available_weight = MAX_BLOCK_WEIGHT - coinbase_weight

# Gather mempool transactions from JSON (each must include "weight", "fee", and "hex")
mempool_txs = []
for txid in mempool_txids:
    tx_path = os.path.join(mempool_dir, f"{txid}.json")
    if os.path.exists(tx_path):
        try:
            with open(tx_path, 'r') as f:
                tx_json = json.load(f)
                tx_weight = int(tx_json.get("weight", 0))
                tx_fee = int(tx_json.get("fee", 0))
                if tx_weight <= available_weight:
                    mempool_txs.append({
                        "txid": txid,
                        "weight": tx_weight,
                        "fee": tx_fee,
                        "feerate": tx_fee / tx_weight if tx_weight else 0,
                        "hex": tx_json.get("hex", "")
                    })
        except Exception:
            continue

# Sort mempool transactions by fee rate (highest first) and select greedily.
mempool_txs.sort(key=lambda tx: tx["feerate"], reverse=True)
total_weight = coinbase_weight
selected_mempool = []
for tx in mempool_txs:
    if total_weight + tx["weight"] <= MAX_BLOCK_WEIGHT:
        selected_mempool.append(tx)
        total_weight += tx["weight"]
while total_weight > MAX_BLOCK_WEIGHT and selected_mempool:
    removed = selected_mempool.pop()
    total_weight -= removed["weight"]

selected_mempool_txids = [tx["txid"] for tx in selected_mempool]

# -----------------------------
# Witness Commitment Calculation Flow
# -----------------------------
# Step 1: For the witness merkle tree:
# - For coinbase, wtxid is defined as 32 zero bytes.
# - For each mempool transaction, compute wtxid = HASH256(full tx hex)
coinbase_wtxid = "00" * 32
wtxids = [coinbase_wtxid]
for tx in selected_mempool:
    full_hex = tx["hex"]
    if full_hex:
        wtxid = double_sha256(bytes.fromhex(full_hex))[::-1].hex()
        wtxids.append(wtxid)

# Step 2: Compute witness merkle root from the wtxids.
witness_merkle_root = compute_merkle_root(wtxids)

# Step 3: Witness commitment input = witness_merkle_root || witness_reserved_value
witness_reserved_value = "00" * 32
witness_commitment_input = bytes.fromhex(witness_merkle_root + witness_reserved_value)

# Step 4: Compute witness commitment = HASH256(witness_commitment_input)
witness_commitment = double_sha256(witness_commitment_input)

# (The final commitment will be prefixed by "6a24aa21a9ed" in the coinbase tx output.)

# Step 5: Recreate coinbase transaction with the computed witness commitment.
coinbase_full, coinbase_nonwitness, coinbase_txid = create_coinbase_tx_with_commitment(witness_commitment)

# -----------------------------
# Assemble Block Header and Mine
# -----------------------------
block_version = int_to_little_endian(0x20000000, 4)
prev_block_hash = bytes.fromhex("0000aaaa00000000000000000000000000000000000000000000000000000000")[::-1]
# Merkle root of txids: coinbase txid first, then selected mempool txids.
all_txids = [coinbase_txid] + selected_mempool_txids
merkle_root_tx = compute_merkle_root(all_txids)
merkle_root_bytes = bytes.fromhex(merkle_root_tx)[::-1]
timestamp = int_to_little_endian(int(time.time()), 4)
bits = int_to_little_endian(0x1f00ffff, 4)
nonce = 0
difficulty_target = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)

found = False
while not found:
    nonce_bytes = int_to_little_endian(nonce, 4)
    header = block_version + prev_block_hash + merkle_root_bytes + timestamp + bits + nonce_bytes
    header_hash = double_sha256(header)
    displayed_hash_int = int.from_bytes(header_hash[::-1], 'big')
    if displayed_hash_int < difficulty_target:
        found = True
    else:
        nonce += 1

block_header_hex = header.hex()

# -----------------------------
# Write out.txt File
# -----------------------------
with open("out.txt", "w") as f:
    f.write(block_header_hex + "\n")
    f.write(coinbase_full + "\n")
    f.write(coinbase_txid + "\n")
    for txid in selected_mempool_txids:
        f.write(txid + "\n")

print("Block mined and out.txt generated successfully.")
