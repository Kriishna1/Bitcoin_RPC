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
# Create a Segwit Coinbase Transaction with Valid Witness Commitment
# -----------------------------
def create_coinbase_tx() -> (str, str, str):
    """
    Create a segwit coinbase transaction.
    The transaction includes:
      - version (4 bytes)
      - segwit marker (0x00) and flag (0x01)
      - 1 input: a coinbase input with prev_txid = 32 zero bytes and index = 0xffffffff,
        a coinbase script ("abcd"), and sequence = 0xffffffff.
      - 2 outputs:
          * Output 1: Block reward (50 BTC) with a simple output script (OP_1)
          * Output 2: Witness commitment output (value = 0) with a script that is:
                OP_RETURN (0x6a) ||
                OP_PUSH 36 (0x24) ||
                4-byte header "aa21a9ed" ||
                32-byte witness commitment
          The witness commitment is computed as:
                double_sha256(witness_merkle_root || witness_reserved_value)
          For the coinbase, the witness list is [32 zero bytes] and the reserved value is 32 zero bytes.
      - locktime = 0
    The coinbase txid is computed from the non-witness serialization.
    
    Returns:
      - full serialized coinbase transaction (hex)
      - non-witness serialization (hex)
      - coinbase txid (hex)
    """
    # Version (4 bytes)
    version = int_to_little_endian(1, 4)
    # Marker and flag for segwit
    marker = b'\x00'
    flag = b'\x01'
    # Input count: 1
    tx_in_count = varint(1)
    # Coinbase input:
    prev_txid = b'\x00' * 32
    prev_index = (0xffffffff).to_bytes(4, 'little')
    coinbase_data = b'abcd'
    coinbase_script = varint(len(coinbase_data)) + coinbase_data
    sequence = (0xffffffff).to_bytes(4, 'little')
    tx_in = prev_txid + prev_index + coinbase_script + sequence

    # Output count: 2
    tx_out_count = varint(2)
    # Output 1: Block reward output: 50 BTC (5000000000 satoshis)
    reward = (5000000000).to_bytes(8, 'little')
    script1 = varint(1) + b'\x51'  # OP_1 is 0x51
    tx_out1 = reward + script1

    # Output 2: Witness commitment output: value = 0
    value2 = (0).to_bytes(8, 'little')
    # Compute witness commitment:
    # For the coinbase, the witness field is a single element of 32 zero bytes.
    witness_element = b'\x00' * 32
    # If there's one element, the witness merkle root is that element's hash (or by definition, the element itself).
    # BIP141 actually defines the witness merkle root as the Merkle tree of the hashes of each witness item.
    # Here we follow: leaf = sha256(witness_element)
    leaf = hashlib.sha256(witness_element).digest()
    witness_merkle_root = leaf  # only one element
    # Witness reserved value is 32 zero bytes.
    witness_reserved_value = b'\x00' * 32
    # Compute commitment = double_sha256(witness_merkle_root || witness_reserved_value)
    commitment = double_sha256(witness_merkle_root + witness_reserved_value)
    # Build the witness commitment output script:
    # It must have: OP_RETURN (0x6a) || OP_PUSH 36 (0x24) || prefix ("aa21a9ed") || commitment (32 bytes)
    prefix = bytes.fromhex("aa21a9ed")
    # The push data is 4 bytes prefix + 32 bytes commitment = 36 bytes, so OP_PUSH data is 0x24.
    script2 = b'\x6a' + b'\x24' + prefix + commitment
    tx_out2 = value2 + varint(len(script2)) + script2

    # Locktime (4 bytes)
    locktime = (0).to_bytes(4, 'little')

    # Witness: one element with length 32 (32 zero bytes)
    witness = varint(1) + varint(32) + (b'\x00' * 32)

    # Full segwit coinbase transaction serialization:
    coinbase_tx_full = (version + marker + flag + tx_in_count + tx_in +
                        tx_out_count + tx_out1 + tx_out2 + witness + locktime)
    # Non-witness serialization for txid computation:
    coinbase_tx_nonwitness = version + tx_in_count + tx_in + tx_out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(coinbase_tx_nonwitness)[::-1].hex()
    return coinbase_tx_full.hex(), coinbase_tx_nonwitness.hex(), coinbase_txid

# -----------------------------
# Process Mempool Transactions
# -----------------------------
# Read all JSON files from the mempool folder.
# IMPORTANT: Each file in the mempool folder should be named "<txid>.json"
mempool_dir = 'mempool'
mempool_txids = []
for filename in os.listdir(mempool_dir):
    if filename.endswith('.json'):
        filepath = os.path.join(mempool_dir, filename)
        try:
            with open(filepath, 'r') as f:
                tx = json.load(f)
                if 'txid' in tx and 'vin' in tx and 'vout' in tx:
                    mempool_txids.append(tx['txid'])
        except Exception:
            continue

# -----------------------------
# Limit Mempool Transactions by Maximum Block Weight
# -----------------------------
# Correct coinbase weight calculation per Bitcoin: weight = (base_size * 3) + total_size.
coinbase_serialized, coinbase_nonwitness, coinbase_txid = create_coinbase_tx()
total_size = len(coinbase_serialized) // 2        # total size (witness-included) in bytes
base_size = len(coinbase_nonwitness) // 2          # non-witness size in bytes
coinbase_weight = base_size * 3 + total_size

# Available weight for mempool transactions.
available_weight = MAX_BLOCK_WEIGHT - coinbase_weight

# Collect valid mempool transactions with their weight, fee, and fee rate.
mempool_txs = []
for txid in mempool_txids:
    tx_path = os.path.join(mempool_dir, f"{txid}.json")
    if os.path.exists(tx_path):
        try:
            with open(tx_path, 'r') as f:
                tx_json = json.load(f)
                tx_weight = int(tx_json.get("weight", 0))
                tx_fee = int(tx_json.get("fee", 0))  # Ensure fee info is present
                if tx_weight <= available_weight:
                    mempool_txs.append({
                        "txid": txid,
                        "weight": tx_weight,
                        "fee": tx_fee,
                        "feerate": tx_fee / tx_weight if tx_weight else 0
                    })
        except Exception:
            continue

# Sort transactions by fee rate (highest first).
mempool_txs.sort(key=lambda tx: tx["feerate"], reverse=True)

# Greedily select transactions while keeping total weight within limit.
total_weight = coinbase_weight
selected_mempool = []
for tx in mempool_txs:
    if total_weight + tx["weight"] <= MAX_BLOCK_WEIGHT:
        selected_mempool.append(tx)
        total_weight += tx["weight"]

# Remove last-added transactions if over the limit.
while total_weight > MAX_BLOCK_WEIGHT and selected_mempool:
    removed = selected_mempool.pop()
    total_weight -= removed["weight"]

selected_mempool_txids = [tx["txid"] for tx in selected_mempool]

# -----------------------------
# Create Coinbase Transaction and Compute Merkle Root
# -----------------------------
# Recreate coinbase transaction (if necessary).
coinbase_serialized, coinbase_nonwitness, coinbase_txid = create_coinbase_tx()
# Block transaction list: coinbase first, then selected mempool transactions.
all_txids = [coinbase_txid] + selected_mempool_txids
merkle_root = compute_merkle_root(all_txids)

# -----------------------------
# Assemble Block Header and Mine
# -----------------------------
block_version = int_to_little_endian(0x20000000, 4)
# Previous block hash (provided in big-endian) stored in little-endian.
prev_block_hash = bytes.fromhex("0000aaaa00000000000000000000000000000000000000000000000000000000")[::-1]
# Merkle root must be in little-endian.
merkle_root_bytes = bytes.fromhex(merkle_root)[::-1]
timestamp = int_to_little_endian(int(time.time()), 4)
# Bits: constant 0x1f00ffff stored in little-endian.
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
    f.write(coinbase_serialized + "\n")
    f.write(coinbase_txid + "\n")
    for txid in selected_mempool_txids:
        f.write(txid + "\n")

print("Block mined and out.txt generated successfully.")
