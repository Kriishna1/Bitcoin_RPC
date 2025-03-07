import os
import json
import time
import hashlib

MAX_BLOCK_WEIGHT = 4000000

def double_sha256(data: bytes) -> bytes:
    """Double SHA-256 hash"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte order of a bytes object"""
    return bytes(reversed(data))

def compute_wtxid(tx_hex: str) -> str:
    """Compute WTXID from transaction hex string"""
    tx_bytes = bytes.fromhex(tx_hex)
    return reverse_bytes(double_sha256(tx_bytes)).hex()

def build_merkle_root(items: list) -> str:
    """Build Merkle root from list of hex strings (little-endian)"""
    if not items:
        return "00" * 32
        
    # Convert hex strings to bytes in big-endian for hashing
    hashes = [reverse_bytes(bytes.fromhex(item)) for item in items]
    
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        next_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            next_hash = double_sha256(combined)
            next_level.append(next_hash)
        hashes = next_level
    
    # Return root as little-endian hex
    return reverse_bytes(hashes[0]).hex()

def create_coinbase_with_commitment(commitment: str) -> tuple:
    """Create coinbase transaction with witness commitment"""
    # Witness reserved value (32 zero bytes)
    witness = bytes.fromhex("00" * 32)
    
    # Coinbase scriptSig (arbitrary data)
    script_sig = bytes.fromhex("03abcd")  # Push 3 bytes: 0xab 0xcd
    
    # Build transaction components
    version = bytes.fromhex("01000000")
    marker_flag = bytes.fromhex("0001")
    input_count = bytes.fromhex("01")
    prev_out = bytes.fromhex("00"*32 + "ffffffff")
    sequence = bytes.fromhex("ffffffff")
    output_count = bytes.fromhex("02")
    
    # Output 1: Reward to miner (50 BTC)
    value1 = bytes.fromhex("00f2052a01000000")  # 50 BTC in satoshis
    script1 = bytes.fromhex("1976a914dbd21b0d86c0c466d9cd421c1ddef96ad7a9493f88ac")
    
    # Output 2: Witness commitment
    value2 = bytes.fromhex("0000000000000000")
    commitment_script = bytes.fromhex("6a24aa21a9ed") + bytes.fromhex(commitment)
    script2 = bytes.fromhex(f"{len(commitment_script):02x}") + commitment_script
    
    # Build transaction
    tx = (version + marker_flag + input_count + prev_out + 
          bytes.fromhex(f"{len(script_sig):02x}") + script_sig + sequence + 
          output_count + value1 + bytes.fromhex(f"{len(script1):02x}") + script1 +
          value2 + bytes.fromhex(f"{len(script2):02x}") + script2 +
          bytes.fromhex("01") + bytes.fromhex("20") + witness +  # Witness data
          bytes.fromhex("00000000"))  # Locktime
    
    return tx.hex(), double_sha256(tx).hex()

# Step 1: Get all transactions
mempool_dir = "mempool"
transactions = []
for filename in os.listdir(mempool_dir):
    if filename.endswith(".json"):
        with open(os.path.join(mempool_dir, filename)) as f:
            tx_data = json.load(f)
            transactions.append({
                "txid": tx_data["txid"],
                "hex": tx_data["hex"],
                "weight": tx_data["weight"]
            })

# Step 2: Create initial coinbase
coinbase_hex, coinbase_txid = create_coinbase_with_commitment("00"*32)

# Step 3: Select transactions (simplified selection)
selected_txs = []
total_weight = 4000  # Initial coinbase weight
for tx in sorted(transactions, key=lambda x: x["weight"], reverse=True):
    if total_weight + tx["weight"] > MAX_BLOCK_WEIGHT:
        break
    selected_txs.append(tx)
    total_weight += tx["weight"]

# Step 4: Calculate wtxids
wtxids = ["00"*32]  # Coinbase wtxid is 32 zero bytes
for tx in selected_txs:
    wtxids.append(compute_wtxid(tx["hex"]))

# Step 5: Compute witness commitment
witness_root = build_merkle_root(wtxids)  # Already little-endian
witness_reserved = "00"*32
commitment_data = bytes.fromhex(witness_root + witness_reserved)
witness_commitment = reverse_bytes(double_sha256(commitment_data)).hex()

# Step 6: Final coinbase with actual commitment
coinbase_hex, coinbase_txid = create_coinbase_with_commitment(witness_commitment)

# Step 7: Build final block
header = bytes.fromhex("04000000")  # Version
header += bytes.fromhex("00"*32)  # Previous block hash
header += bytes.fromhex(build_merkle_root([coinbase_txid] + [tx["txid"] for tx in selected_txs]))
header += int(time.time()).to_bytes(4, "little")
header += bytes.fromhex("ffff001f")  # Bits
header += (0).to_bytes(4, "little")  # Nonce (to be mined)

# Mining loop (simplified)
target = bytes.fromhex("0000ffff00000000000000000000000000000000000000000000000000000000")
while True:
    block_hash = double_sha256(header)
    if block_hash < target:
        break
    header = header[:-4] + (int.from_bytes(header[-4:], "little") + 1).to_bytes(4, "little")

# Write output
with open("out.txt", "w") as f:
    f.write(header.hex() + "\n")
    f.write(coinbase_hex + "\n")
    f.write(coinbase_txid + "\n")
    for tx in selected_txs:
        f.write(tx["txid"] + "\n")