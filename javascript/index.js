const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');

// -----------------------------
// Helper Functions (inlined)
// -----------------------------

// Difficulty target (provided)
const DIFFICULTY = Buffer.from('0000ffff00000000000000000000000000000000000000000000000000000000', 'hex');
// Witness reserved value: 32 zero bytes.
const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0);

// double_sha256: returns a Buffer.
function double_sha256(data) {
  const h1 = crypto.createHash('sha256').update(data).digest();
  return crypto.createHash('sha256').update(h1).digest();
}

// hash256: double SHA256; input as hex string, output as hex string.
function hash256(inputHex) {
  const h1 = crypto.createHash('sha256').update(Buffer.from(inputHex, 'hex')).digest();
  return crypto.createHash('sha256').update(h1).digest('hex');
}

// intToLE: convert integer to little-endian Buffer.
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

// generateMerkleRoot: compute merkle root from an array of hex strings.
function generateMerkleRoot(txids) {
  if (txids.length === 0) return '00'.repeat(32);
  let level = txids.map(txid => Buffer.from(txid, 'hex').reverse().toString('hex'));
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      let pair;
      if (i + 1 === level.length) {
        pair = level[i] + level[i];
      } else {
        pair = level[i] + level[i+1];
      }
      const h1 = crypto.createHash('sha256').update(Buffer.from(pair, 'hex')).digest();
      const h2 = crypto.createHash('sha256').update(h1).digest();
      nextLevel.push(h2.reverse().toString('hex'));
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

// -----------------------------
// Coinbase Transaction Creation
// -----------------------------
/*
  createCoinbaseTxWithCommitment(commitment)
    Builds a coinbase transaction with:
    - One input (coinbase) with coinbase data "abcd".
    - Two outputs:
        * Output 1: block reward (50 BTC) with a simple script (OP_1).
        * Output 2: Witness commitment output with script:
            OP_RETURN (0x6a) || OP_PUSHBYTES_36 (0x24) || 0xaa21a9ed || [commitment]
    - The witness for the coinbase input is initially empty (for dummy creation).
    Returns:
      { full, nonWitness, txid }
*/
function createCoinbaseTxWithCommitment(commitment) {
  const version = intToLE(1, 4);
  const marker = Buffer.from([0x00]);
  const flag = Buffer.from([0x01]);
  const txInCount = varint(1);
  const prevTxid = Buffer.alloc(32, 0);
  const prevIndex = intToLE(0xffffffff, 4);
  const coinbaseData = Buffer.from("abcd", "utf8");
  const coinbaseScript = Buffer.concat([varint(coinbaseData.length), coinbaseData]);
  const sequence = intToLE(0xffffffff, 4);
  const txIn = Buffer.concat([prevTxid, prevIndex, coinbaseScript, sequence]);
  
  const txOutCount = varint(2);
  // Output 1: block reward (50 BTC)
  const reward = intToLE(5000000000, 8);
  const script1 = Buffer.concat([varint(1), Buffer.from([0x51])]); // OP_1
  const txOut1 = Buffer.concat([reward, varint(script1.length), script1]);
  
  // Output 2: Witness commitment output.
  // Build script: OP_RETURN (0x6a) || OP_PUSHBYTES_36 (0x24) || prefix (0xaa21a9ed) || commitment
  const value2 = intToLE(0, 8);
  const prefix = Buffer.from("aa21a9ed", "hex");
  const script2 = Buffer.concat([Buffer.from([0x6a, 0x24]), prefix, commitment]);
  const txOut2 = Buffer.concat([value2, varint(script2.length), script2]);
  
  const locktime = intToLE(0, 4);
  // Initially, set witness to empty (we will later update it)
  const witness = Buffer.concat([varint(0)]);
  
  const fullTx = Buffer.concat([version, marker, flag, txInCount, txIn, txOutCount, txOut1, txOut2, witness, locktime]);
  const nonWitnessTx = Buffer.concat([version, txInCount, txIn, txOutCount, txOut1, txOut2, locktime]);
  const txid = double_sha256(nonWitnessTx).reverse().toString('hex');
  
  return { full: fullTx.toString('hex'), nonWitness: nonWitnessTx.toString('hex'), txid };
}

/*
  updateCoinbaseTx(commitment):
    Rebuilds the coinbase transaction with the valid witness commitment output,
    and sets the coinbase witness stack to contain the reserved value (32 zero bytes).
*/
function updateCoinbaseTx(commitment) {
  const version = intToLE(1, 4);
  const marker = Buffer.from([0x00]);
  const flag = Buffer.from([0x01]);
  const txInCount = varint(1);
  const prevTxid = Buffer.alloc(32, 0);
  const prevIndex = intToLE(0xffffffff, 4);
  const coinbaseData = Buffer.from("abcd", "utf8");
  const coinbaseScript = Buffer.concat([varint(coinbaseData.length), coinbaseData]);
  const sequence = intToLE(0xffffffff, 4);
  const txIn = Buffer.concat([prevTxid, prevIndex, coinbaseScript, sequence]);
  
  const txOutCount = varint(2);
  const reward = intToLE(5000000000, 8);
  const script1 = Buffer.concat([varint(1), Buffer.from([0x51])]);
  const txOut1 = Buffer.concat([reward, varint(script1.length), script1]);
  
  // New Output 2: Witness commitment output with our computed commitment.
  const value2 = intToLE(0, 8);
  const prefix = Buffer.from("aa21a9ed", "hex");
  const script2 = Buffer.concat([Buffer.from([0x6a, 0x24]), prefix, commitment]);
  const txOut2 = Buffer.concat([value2, varint(script2.length), script2]);
  
  const locktime = intToLE(0, 4);
  // Now, set witness stack to contain the reserved value (32 zeros)
  const witness = Buffer.concat([varint(1), varint(32), Buffer.alloc(32, 0)]);
  
  const fullTx = Buffer.concat([version, marker, flag, txInCount, txIn, txOutCount, txOut1, txOut2, witness, locktime]);
  const nonWitnessTx = Buffer.concat([version, txInCount, txIn, txOutCount, txOut1, txOut2, locktime]);
  const txid = double_sha256(nonWitnessTx).reverse().toString('hex');
  
  return { full: fullTx.toString('hex'), nonWitness: nonWitnessTx.toString('hex'), txid };
}

// -----------------------------
// Process Mempool Transactions
// -----------------------------
const mempoolDir = path.join(__dirname, "mempool");
let mempoolTxids = [];
let mempoolTxHexes = {};
fs.readdirSync(mempoolDir).forEach(file => {
  if (file.endsWith('.json') && file !== "mempool.json") {
    const content = fs.readFileSync(path.join(mempoolDir, file), "utf8");
    try {
      const tx = JSON.parse(content);
      if (tx.txid && tx.vin && tx.vout && tx.hex) {
        mempoolTxids.push(tx.txid);
        mempoolTxHexes[tx.txid] = tx.hex;
      }
    } catch (e) {
      // ignore errors
    }
  }
});

// -----------------------------
// Limit Mempool Transactions by Maximum Block Weight
// -----------------------------
// Calculate coinbase weight using Bitcoin formula: weight = (base size * 3) + total size.
const coinbaseDummy = createCoinbaseTxWithCommitment(Buffer.alloc(32, 0));
const totalSize = coinbaseDummy.full.length / 2;
const baseSize = coinbaseDummy.nonWitness.length / 2;
const coinbaseWeight = baseSize * 3 + totalSize;
const availableWeight = MAX_BLOCK_WEIGHT - coinbaseWeight;

// Gather mempool transactions (each JSON must include "weight", "fee", and "hex").
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
    } catch (e) {
      // ignore errors
    }
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
// Step 1: Compute wtxids.
// For coinbase, wtxid is defined as 32 zero bytes.
const coinbaseWtxid = "00".repeat(32);
let wtxids = [coinbaseWtxid];
for (const tx of selectedMempool) {
  const fullHex = tx.hex;
  if (fullHex) {
    const wtxid = double_sha256(Buffer.from(fullHex, 'hex')).reverse().toString('hex');
    wtxids.push(wtxid);
  }
}

// Step 2: Compute witness merkle root from wtxids.
const witnessMerkleRoot = generateMerkleRoot(wtxids);

// Step 3: Witness commitment input = witnessMerkleRoot || witness_reserved_value (32 zeros)
const witnessReservedValueHex = "00".repeat(32);
const witnessCommitmentInput = witnessMerkleRoot + witnessReservedValueHex;

// Step 4: Compute witness commitment = hash256(witnessCommitmentInput)
const witnessCommitmentHex = hash256(witnessCommitmentInput);
const witnessCommitment = Buffer.from(witnessCommitmentHex, 'hex');

// -----------------------------
// Rebuild Coinbase Transaction with Valid Witness Commitment
// -----------------------------
const updatedCoinbase = updateCoinbaseTx(witnessCommitment);
const coinbaseFull = updatedCoinbase.full;
const coinbaseTxidFinal = updatedCoinbase.txid;

// -----------------------------
// Assemble Block Header and Mine
// -----------------------------
const blockVersion = intToLE(0x20000000, 4);
const prevBlockHash = Buffer.from("0000aaaa00000000000000000000000000000000000000000000000000000000", "hex").reverse();
const allTxids = [coinbaseTxidFinal, ...selectedMempoolTxids];
const merkleRootTx = generateMerkleRoot(allTxids);
const merkleRootBytes = Buffer.from(merkleRootTx, "hex").reverse();
const timestamp = intToLE(Math.floor(Date.now() / 1000), 4);
const bits = intToLE(0x1f00ffff, 4);
let nonce = 0;
const difficultyTarget = BigInt("0x" + DIFFICULTY.toString('hex'));
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
// Write out.txt
// -----------------------------
const outLines = [];
outLines.push(blockHeaderHex);
outLines.push(coinbaseFull);
outLines.push(coinbaseTxidFinal);
selectedMempoolTxids.forEach(txid => outLines.push(txid));
fs.writeFileSync("out.txt", outLines.join("\n"));

console.log("Block mined and out.txt generated successfully.");
