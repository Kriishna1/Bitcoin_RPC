const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// -----------------------------
// Helper Functions
// -----------------------------

// Difficulty target (as provided)
const difficulty = Buffer.from('0000ffff00000000000000000000000000000000000000000000000000000000', 'hex');
// Witness reserved value: 32 zero bytes
const WITNESS_RESERVED_VALUE = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex');

// hash256: double SHA256, input as hex string, output as hex string.
function hash256(input) {
  const h1 = crypto.createHash('sha256').update(Buffer.from(input, 'hex')).digest();
  return crypto.createHash('sha256').update(h1).digest('hex');
}

// generateMerkleRoot: build merkle root from an array of hex strings.
function generateMerkleRoot(txids) {
  if (txids.length === 0) return null;
  // Reverse each txid for internal hashing.
  let level = txids.map((txid) => Buffer.from(txid, 'hex').reverse().toString('hex'));
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      let pairHash;
      if (i + 1 === level.length) {
        pairHash = hash256(level[i] + level[i]);
      } else {
        pairHash = hash256(level[i] + level[i + 1]);
      }
      nextLevel.push(pairHash);
    }
    level = nextLevel;
  }
  return level[0];
}

// calculateWitnessCommitment: witness commitment = hash256(witnessMerkleRoot || witnessReservedValue)
function calculateWitnessCommitment(wtxids) {
  const witnessRoot = generateMerkleRoot(wtxids);
  const reservedHex = WITNESS_RESERVED_VALUE.toString('hex');
  return hash256(witnessRoot + reservedHex);
}

// double_sha256: compute double SHA256 hash, input Buffer, output Buffer.
function double_sha256(data) {
  const h1 = crypto.createHash('sha256').update(data).digest();
  return crypto.createHash('sha256').update(h1).digest();
}

// intToLE: convert integer to little-endian Buffer of given byte length.
function intToLE(num, bytes) {
  const buf = Buffer.alloc(bytes);
  buf.writeUIntLE(num, 0, bytes);
  return buf;
}

// varint: Bitcoin varint encoding.
function varint(n) {
  if (n < 0xfd) return Buffer.from([n]);
  else if (n <= 0xffff) return Buffer.concat([Buffer.from([0xfd]), intToLE(n, 2)]);
  else if (n <= 0xffffffff) return Buffer.concat([Buffer.from([0xfe]), intToLE(n, 4)]);
  else return Buffer.concat([Buffer.from([0xff]), intToLE(n, 8)]);
}

// -----------------------------
// Coinbase Transaction with Witness Commitment
// -----------------------------
function createCoinbaseTxWithCommitment(commitment) {
  // Coinbase tx structure:
  // [version (4)] [marker (1)] [flag (1)] [txInCount] [txIn] [txOutCount] [txOut1] [txOut2] [witness] [locktime (4)]
  const version = intToLE(1, 4);
  const marker = Buffer.from([0x00]);
  const flag = Buffer.from([0x01]);
  const txInCount = varint(1);
  // Coinbase input: prevout = 32 zero bytes, index = 0xffffffff, coinbase script = "abcd", sequence = 0xffffffff.
  const prevTxid = Buffer.alloc(32, 0);
  const prevIndex = intToLE(0xffffffff, 4);
  const coinbaseData = Buffer.from("abcd", "utf8");
  const coinbaseScript = Buffer.concat([varint(coinbaseData.length), coinbaseData]);
  const sequence = intToLE(0xffffffff, 4);
  const txIn = Buffer.concat([prevTxid, prevIndex, coinbaseScript, sequence]);
  
  const txOutCount = varint(2);
  // Output 1: Block reward: 50 BTC
  const reward = intToLE(5000000000, 8);
  const script1 = Buffer.concat([varint(1), Buffer.from([0x51])]); // OP_1 (0x51)
  const txOut1 = Buffer.concat([reward, varint(script1.length), script1]);
  // Output 2: Witness commitment output: value = 0, script = OP_RETURN || OP_PUSH36 || "aa21a9ed" || commitment
  const value2 = intToLE(0, 8);
  const prefix = Buffer.from("aa21a9ed", "hex");
  const script2 = Buffer.concat([Buffer.from([0x6a]), Buffer.from([0x24]), prefix, commitment]);
  const txOut2 = Buffer.concat([value2, varint(script2.length), script2]);
  
  const locktime = intToLE(0, 4);
  // Witness: For coinbase, defined as one element of 32 zero bytes.
  const witness = Buffer.concat([varint(1), varint(32), Buffer.alloc(32, 0)]);
  
  const coinbaseTxFull = Buffer.concat([version, marker, flag, txInCount, txIn, txOutCount, txOut1, txOut2, witness, locktime]);
  const coinbaseTxNonWitness = Buffer.concat([version, txInCount, txIn, txOutCount, txOut1, txOut2, locktime]);
  const coinbaseTxid = double_sha256(coinbaseTxNonWitness).reverse().toString('hex');
  
  return { full: coinbaseTxFull.toString('hex'), nonWitness: coinbaseTxNonWitness.toString('hex'), txid: coinbaseTxid };
}

// -----------------------------
// Process Mempool Transactions
// -----------------------------
const mempoolDir = path.join(__dirname, "mempool");
let mempoolTxids = [];
let mempoolTxHexes = {}; // map txid -> full hex
fs.readdirSync(mempoolDir).forEach(file => {
  if (file.endsWith('.json') && file !== "mempool.json") {
    const content = fs.readFileSync(path.join(mempoolDir, file), "utf8");
    try {
      const tx = JSON.parse(content);
      if (tx.txid && tx.vin && tx.vout && tx.hex) {
        mempoolTxids.push(tx.txid);
        mempoolTxHexes[tx.txid] = tx.hex;
      }
    } catch (e) { /* ignore errors */ }
  }
});

// -----------------------------
// Limit Mempool Transactions by Maximum Block Weight
// -----------------------------
const MAX_BLOCK_WEIGHT = 4000000;

// Calculate coinbase weight using Bitcoin's formula:
// weight = (base_size * 3) + total_size, where sizes are in bytes.
const coinbaseDummy = createCoinbaseTxWithCommitment(Buffer.alloc(32, 0));
const totalSize = coinbaseDummy.full.length / 2;
const baseSize = coinbaseDummy.nonWitness.length / 2;
const coinbaseWeight = baseSize * 3 + totalSize;
const availableWeight = MAX_BLOCK_WEIGHT - coinbaseWeight;

// Gather mempool transactions (each JSON must include "weight", "fee", and "hex")
let mempoolTxs = [];
mempoolTxids.forEach(txid => {
  const txPath = path.join(mempoolDir, `${txid}.json`);
  if (fs.existsSync(txPath)) {
    try {
      const txJson = JSON.parse(fs.readFileSync(txPath, "utf8"));
      const txWeight = parseInt(txJson.weight || "0", 10);
      const txFee = parseInt(txJson.fee || "0", 10);
      if (txWeight <= availableWeight) {
        mempoolTxs.push({
          txid,
          weight: txWeight,
          fee: txFee,
          feerate: txFee / txWeight,
          hex: txJson.hex
        });
      }
    } catch (e) { /* ignore errors */ }
  }
});
mempoolTxs.sort((a, b) => b.feerate - a.feerate);
let totalWeight = coinbaseWeight;
let selectedMempool = [];
for (const tx of mempoolTxs) {
  if (totalWeight + tx.weight <= MAX_BLOCK_WEIGHT) {
    selectedMempool.push(tx);
    totalWeight += tx.weight;
  }
}
while (totalWeight > MAX_BLOCK_WEIGHT && selectedMempool.length > 0) {
  const removed = selectedMempool.pop();
  totalWeight -= removed.weight;
}
const selectedMempoolTxids = selectedMempool.map(tx => tx.txid);

// -----------------------------
// Witness Commitment Calculation Flow
// -----------------------------
// Step 1: Compute wtxids for all transactions.
// For coinbase, by BIP141 the wtxid is defined as 32 zero bytes.
const coinbaseWtxid = "00".repeat(32);
let wtxids = [coinbaseWtxid];
selectedMempool.forEach(tx => {
  const fullHex = tx.hex;
  if (fullHex) {
    // wtxid = double_sha256(full_tx_hex) (with reversal)
    const wtxid = double_sha256(Buffer.from(fullHex, 'hex')).reverse().toString('hex');
    wtxids.push(wtxid);
  }
});

// Step 2: Compute witness merkle root from wtxids.
const witnessMerkleRoot = generateMerkleRoot(wtxids);

// Step 3: Witness commitment input = witnessMerkleRoot || witness_reserved_value (32 zeros)
const witnessReservedValueHex = "00".repeat(32);
const witnessCommitmentInput = witnessMerkleRoot + witnessReservedValueHex;

// Step 4: Compute witness commitment = hash256(input) (double SHA256, output hex)
const witnessCommitment = Buffer.from(hash256(witnessCommitmentInput), 'hex');

// -----------------------------
// Rebuild Coinbase Transaction with Computed Witness Commitment
// -----------------------------
const coinbase = createCoinbaseTxWithCommitment(witnessCommitment);
const coinbaseFull = coinbase.full;
const coinbaseTxidFinal = coinbase.txid;

// -----------------------------
// Assemble Block Header and Mine
// -----------------------------
const blockVersion = intToLE(0x20000000, 4);
let prevBlockHash = Buffer.from("0000aaaa00000000000000000000000000000000000000000000000000000000", "hex").reverse();
const allTxids = [coinbaseTxidFinal, ...selectedMempoolTxids];
const merkleRootTx = computeMerkleRoot(allTxids);
const merkleRootBytes = Buffer.from(merkleRootTx, "hex").reverse();
const timestamp = intToLE(Math.floor(Date.now() / 1000), 4);
const bits = intToLE(0x1f00ffff, 4);
let nonce = 0;
const difficultyTarget = BigInt("0x" + difficulty.toString('hex'));
let header, headerHash;
while (true) {
  const nonceBuf = intToLE(nonce, 4);
  header = Buffer.concat([blockVersion, prevBlockHash, merkleRootBytes, timestamp, bits, nonceBuf]);
  headerHash = double_sha256(header);
  const displayedHash = Buffer.from(headerHash).reverse();
  const hashInt = BigInt("0x" + displayedHash.toString('hex'));
  if (hashInt < difficultyTarget) break;
  nonce++;
}
const blockHeaderHex = header.toString('hex');

// -----------------------------
// Write out.txt File
// -----------------------------
const outLines = [];
outLines.push(blockHeaderHex);
outLines.push(coinbaseFull);
outLines.push(coinbaseTxidFinal);
selectedMempoolTxids.forEach(txid => outLines.push(txid));
fs.writeFileSync("out.txt", outLines.join("\n"));

console.log("Block mined and out.txt generated successfully.");
