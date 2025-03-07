import os
import json
import time
import hashlib

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
    # Return final hash in big-endian hex
    return hashes[0][::-1].hex()

# -----------------------------
# Create a Segwit Coinbase Transaction
# -----------------------------
def create_coinbase_tx() -> (str, str):
    """
    Create a segwit coinbase transaction.
    The transaction includes:
      - version (4 bytes)
      - segwit marker (0x00) and flag (0x01)
      - 1 input: a coinbase input with prev_txid = 32 zero bytes and index = 0xffffffff,
        a coinbase script (here, 4 arbitrary bytes "abcd"),
        and a sequence of 0xffffffff.
      - 2 outputs:
          * Output 1: block reward (50 BTC) with a simple output script (OP_1)
          * Output 2: witness commitment output (OP_RETURN with a 36-byte payload,
            which is 4-byte header "aa21a9ed" followed by 32 zero bytes)
      - Witness: one witness element whose length is 0 (reserved value)
      - locktime = 0
    The coinbase txid is computed from the non-witness serialization.
    """
    # Version (4 bytes)
    version = int_to_little_endian(1, 4)
    # Marker and flag (for segwit)
    marker = b'\x00'
    flag = b'\x01'
    # Input count: 1
    tx_in_count = varint(1)
    # Coinbase input:
    prev_txid = b'\x00' * 32
    prev_index = (0xffffffff).to_bytes(4, 'little')
    # Coinbase data: 4 arbitrary bytes, e.g., "abcd"
    coinbase_data = b'abcd'
    coinbase_script = varint(len(coinbase_data)) + coinbase_data
    sequence = (0xffffffff).to_bytes(4, 'little')
    tx_in = prev_txid + prev_index + coinbase_script + sequence

    # Output count: 2
    tx_out_count = varint(2)
    # Output 1: Block reward output: 50 BTC (5000000000 satoshis)
    reward = (5000000000).to_bytes(8, 'little')
    # Simple output script: push 1 byte (OP_1, 0x51)
    script1 = varint(1) + b'\x51'
    tx_out1 = reward + script1

    # Output 2: Witness commitment output: value = 0
    value2 = (0).to_bytes(8, 'little')
    # Witness commitment script:
    # OP_RETURN (0x6a) followed by push of 36 bytes:
    # 4-byte header "aa21a9ed" + 32 bytes of zeros.
    witness_commitment_data = bytes.fromhex("aa21a9ed") + (b'\x00' * 32)
    script2 = b'\x6a' + varint(len(witness_commitment_data)) + witness_commitment_data
    tx_out2 = value2 + varint(len(script2)) + script2

    # Locktime (4 bytes)
    locktime = (0).to_bytes(4, 'little')

    # Witness: one element with 0-length (the reserved value)
    witness = varint(1) + varint(32) + (b'\x00' * 32)

    # Full segwit coinbase transaction serialization:
    coinbase_tx_full = (version + marker + flag + tx_in_count + tx_in +
                        tx_out_count + tx_out1 + tx_out2 + witness + locktime)
    # Non-witness serialization for txid computation:
    coinbase_tx_non_witness = version + tx_in_count + tx_in + tx_out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(coinbase_tx_non_witness)[::-1].hex()
    return coinbase_tx_full.hex(), coinbase_txid

# -----------------------------
# Process Mempool Transactions
# -----------------------------
# Read all JSON files from the mempool folder.
# IMPORTANT: Ensure that each file in the mempool folder is named exactly "<txid>.json"
# (for example, "00000964b698b728022e6d180add7b2c060676e522ab2907f06198af7b2d0b99.json")
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
# Create Coinbase Transaction and Compute Merkle Root
# -----------------------------
coinbase_serialized, coinbase_txid = create_coinbase_tx()
# The block’s transaction list is: coinbase first, then all mempool transactions.
all_txids = [coinbase_txid] + mempool_txids
merkle_root = compute_merkle_root(all_txids)

# -----------------------------
# Assemble Block Header and Mine
# -----------------------------
# Block header fields:
block_version = int_to_little_endian(0x20000000, 4)
# Previous block hash (given value) – stored in little-endian in the header
prev_block_hash = bytes.fromhex("0000aaaa00000000000000000000000000000000000000000000000000000000")
# Merkle root must be in little-endian
merkle_root_bytes = bytes.fromhex(merkle_root)[::-1]
timestamp = int_to_little_endian(int(time.time()), 4)
# Bits field: must be stored in little-endian.
# We set it to the constant 0x1f00ffff. (Avoid any accidental reversal.)
bits = int_to_little_endian(0x1f00ffff, 4)
nonce = 0

# Difficulty target as a 256-bit integer (big-endian)
difficulty_target = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)

found = False
while not found:
    nonce_bytes = int_to_little_endian(nonce, 4)
    # Assemble the header:
    # Note: prev_block_hash and merkle_root are stored in little-endian (so we reverse the given big-endian values)
    header = block_version + prev_block_hash[::-1] + merkle_root_bytes + timestamp + bits + nonce_bytes
    header_hash = double_sha256(header)
    # IMPORTANT: The displayed block hash is the reversed header_hash.
    # Compare the displayed hash (interpreted as big-endian) with the difficulty target.
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
    # First line: block header (80 bytes in hex)
    f.write(block_header_hex + "\n")
    # Second line: serialized coinbase transaction
    f.write(coinbase_serialized + "\n")
    # Subsequent lines: coinbase txid followed by each mempool txid
    f.write(coinbase_txid + "\n")
    for txid in mempool_txids:
        f.write(txid + "\n")

print("Block mined and out.txt generated successfully.")
