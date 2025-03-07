/*******************************************************
 * index.js
 * Example single-file solution using:
 *   - fs, path, crypto
 *   - bitcoinjs-lib
 *******************************************************/

const fs = require('fs');
const path = require('path');
const { createHash, randomBytes } = require('crypto');
const bitcoin = require('bitcoinjs-lib');

// Difficulty target and constants
const DIFFICULTY_TARGET_HEX = '0000ffff00000000000000000000000000000000000000000000000000000000';
const MAX_BLOCK_WEIGHT = 4000000;
const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0); // 32 zero bytes

// Double-SHA256 helper
function doubleSha256(buffer) {
  const h1 = createHash('sha256').update(buffer).digest();
  return createHash('sha256').update(h1).digest();
}

// Convert integer to little-endian Buffer
function intToLE(num, bytes) {
  const buf = Buffer.alloc(bytes);
  buf.writeUIntLE(num, 0, bytes);
  return buf;
}

// Read all mempool transactions from ./mempool directory
// Each file must contain JSON with "txid", "vin", "vout", "hex", "weight", "fee"
const mempoolDir = path.join(__dirname, 'mempool');
const mempoolTxs = [];
fs.readdirSync(mempoolDir).forEach(file => {
  if (file.endsWith('.json') && file !== 'mempool.json') {
    const data = fs.readFileSync(path.join(mempoolDir, file), 'utf8');
    try {
      const tx = JSON.parse(data);
      if (tx.txid && tx.vin && tx.vout && tx.hex && tx.weight && tx.fee !== undefined) {
        mempoolTxs.push(tx);
      }
    } catch (e) {
      // ignore parse errors
    }
  }
});

//------------------------------------------------------------------
// 1. Create an initial coinbase transaction with a dummy commitment
//------------------------------------------------------------------
function createCoinbaseDummy() {
  // We'll use bitcoinjs-lib to build a basic segwit coinbase transaction
  // with a placeholder (dummy) witness commitment.

  // Create a new transaction
  const txb = new bitcoin.TransactionBuilder();
  txb.setVersion(1);

  // Coinbase input: prevout = 32 zero bytes, index=0xffffffff
  // ScriptSig = "abcd" (arbitrary)
  const dummyPrevout = Buffer.alloc(32, 0);
  // For TransactionBuilder, addInput expects a dummy txid and index
  // We'll override the raw input in the final hex
  txb.addInput(dummyPrevout.toString('hex'), 0xffffffff);

  // Output 1: block reward: 50 BTC
  const reward = 50e8;
  // For simplicity, we'll use a single opcode OP_1 as the scriptPubKey
  const scriptPubKey1 = bitcoin.script.compile([bitcoin.opcodes.OP_1]);
  txb.addOutput(scriptPubKey1, reward);

  // Output 2: dummy witness commitment
  // e.g. OP_RETURN (0x6a) + push 36 bytes + "aa21a9ed" + 32 zeros
  const prefix = Buffer.from('aa21a9ed', 'hex');
  const dummyCommitment = Buffer.alloc(32, 0);
  const script2 = bitcoin.script.compile([
    bitcoin.opcodes.OP_RETURN,
    Buffer.concat([prefix, dummyCommitment])
  ]);
  txb.addOutput(script2, 0);

  // Build the transaction
  const tx = txb.buildIncomplete();

  // The transaction's first input is coinbase; set the coinbase scriptSig
  // We do it in raw hex
  tx.ins[0].script = Buffer.concat([
    Buffer.from([4]), // length
    Buffer.from('abcd', 'utf8')
  ]);

  // Convert to segwit: we need the marker/flag
  // We'll manually set a single witness item of empty
  tx.ins[0].witness = []; // empty for now

  return tx;
}

// Create the dummy coinbase
let coinbaseTx = createCoinbaseDummy();

//------------------------------------------------------------------
// 2. Compute coinbase weight
//------------------------------------------------------------------
function transactionWeight(tx) {
  // bitcoinjs-lib doesn't have a built-in weight() method,
  // so we do the standard formula:
  // weight = baseSize * 3 + totalSize
  const fullHex = tx.toHex();
  const totalSize = fullHex.length / 2; // in bytes
  // Non-witness serialization: remove witness data
  // For simplicity, we can re-build the transaction with no witness
  // or use the toBuffer() with some hack. We'll do a quick manual approach:
  const clone = tx.clone();
  clone.ins.forEach(i => (i.witness = []));
  const baseHex = clone.toHex();
  const baseSize = baseHex.length / 2;
  return baseSize * 3 + totalSize;
}

const coinbaseWeight = transactionWeight(coinbaseTx);
const availableWeight = MAX_BLOCK_WEIGHT - coinbaseWeight;

//------------------------------------------------------------------
// 3. Filter mempool transactions by weight (for demonstration)
//------------------------------------------------------------------
let selectedTxs = [];
let totalWeight = coinbaseWeight;
mempoolTxs.sort((a, b) => (b.fee / b.weight) - (a.fee / a.weight)); // sort by feerate descending

for (const tx of mempoolTxs) {
  if (totalWeight + tx.weight <= MAX_BLOCK_WEIGHT) {
    selectedTxs.push(tx);
    totalWeight += tx.weight;
  }
}
while (totalWeight > MAX_BLOCK_WEIGHT && selectedTxs.length > 0) {
  const removed = selectedTxs.pop();
  totalWeight -= removed.weight;
}

//------------------------------------------------------------------
// 4. Compute wtxids
//------------------------------------------------------------------
// For the coinbase, per BIP141, wtxid is 32 zero bytes
const coinbaseWtxid = '00'.repeat(32);

// For mempool transactions, wtxid = doubleSha256 of the full hex (reversed for display)
function computeWtxid(fullHex) {
  const buf = Buffer.from(fullHex, 'hex');
  const hash = doubleSha256(buf);
  return hash.reverse().toString('hex');
}

let wtxids = [coinbaseWtxid];
for (const tx of selectedTxs) {
  const wtxid = computeWtxid(tx.hex);
  wtxids.push(wtxid);
}

//------------------------------------------------------------------
// 5. Compute witness merkle root
//------------------------------------------------------------------
function generateMerkleRootJs(txids) {
  if (txids.length === 0) return '00'.repeat(32);
  let level = txids.map((txid) => {
    const buf = Buffer.from(txid, 'hex');
    return buf.reverse().toString('hex');
  });
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      let pair;
      if (i + 1 === level.length) {
        pair = level[i] + level[i];
      } else {
        pair = level[i] + level[i + 1];
      }
      // doubleSha256
      const h1 = createHash('sha256').update(Buffer.from(pair, 'hex')).digest();
      const h2 = createHash('sha256').update(h1).digest();
      nextLevel.push(h2.reverse().toString('hex'));
    }
    level = nextLevel;
  }
  return level[0];
}
const witnessMerkleRootHex = generateMerkleRootJs(wtxids);

// Combine witness merkle root + reserved value
const witnessCommitmentInputHex = witnessMerkleRootHex + WITNESS_RESERVED_VALUE.toString('hex');
const witnessCommitmentHash = createHash('sha256')
  .update(createHash('sha256').update(Buffer.from(witnessCommitmentInputHex, 'hex')).digest())
  .digest(); // final 32 bytes

//------------------------------------------------------------------
// 6. Update the coinbase with the final witness commitment
//------------------------------------------------------------------
function updateCoinbaseTx(coinbase, commitment) {
  // We'll rebuild the second output's scriptPubKey
  // OP_RETURN (0x6a), OP_PUSH36 (0x24), 0xaa21a9ed, 32-byte commitment
  const prefix = Buffer.from('aa21a9ed', 'hex');
  const script2 = Buffer.concat([Buffer.from([0x6a, 0x24]), prefix, commitment]);
  // We'll also set the coinbase input's witness to contain the 32-byte reserved value
  // For demonstration, we re-build the entire transaction using bitcoinjs-lib
  const txb = new bitcoin.TransactionBuilder();
  txb.setVersion(1);

  // Add coinbase input
  // We must replicate the coinbase scriptSig "abcd"
  const dummyPrevout = Buffer.alloc(32, 0);
  txb.addInput(dummyPrevout.toString('hex'), 0xffffffff);
  // Output 1: block reward
  const reward = 50e8;
  const script1 = bitcoin.script.compile([bitcoin.opcodes.OP_1]);
  txb.addOutput(script1, reward);
  // Output 2: new witness commitment
  txb.addOutput(script2, 0);

  const txFinal = txb.buildIncomplete();
  // Set coinbase scriptSig to "abcd"
  txFinal.ins[0].script = Buffer.concat([
    Buffer.from([4]),
    Buffer.from('abcd', 'utf8')
  ]);
  // Set coinbase witness stack: one item = reserved value (32 zero bytes)
  txFinal.ins[0].witness = [WITNESS_RESERVED_VALUE];

  return txFinal;
}

coinbaseTx = updateCoinbaseTx(coinbaseTx, witnessCommitmentHash);

// Compute final coinbase txid (non-witness)
const coinbaseCloneNoWitness = coinbaseTx.clone();
coinbaseCloneNoWitness.ins.forEach(i => (i.witness = []));
const coinbaseTxidFinal = doubleSha256(coinbaseCloneNoWitness.toBuffer()).reverse().toString('hex');

//------------------------------------------------------------------
// 7. Build the block header and mine
//------------------------------------------------------------------
function computeRegularMerkleRoot(txids) {
  // For the block's normal Merkle root, we use the normal txids
  // which in this example is coinbase + each mempool txid
  // We'll use a small JS helper
  const reverseHex = (hex) => Buffer.from(hex, 'hex').reverse().toString('hex');
  let level = txids.map(txid => reverseHex(txid));
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      let pair;
      if (i + 1 === level.length) {
        pair = level[i] + level[i];
      } else {
        pair = level[i] + level[i + 1];
      }
      const h1 = createHash('sha256').update(Buffer.from(pair, 'hex')).digest();
      const h2 = createHash('sha256').update(h1).digest();
      nextLevel.push(h2.reverse().toString('hex'));
    }
    level = nextLevel;
  }
  return level[0] || '00'.repeat(32);
}

// The final block txids: coinbase first, then the mempool txids
const finalTxids = [coinbaseTxidFinal, ...selectedTxs.map(t => t.txid)];
const blockMerkleRootHex = computeRegularMerkleRoot(finalTxids);

// Build an 80-byte header: [version(4), prevBlockHash(32, LE), merkleRoot(32, LE), timestamp(4, LE), bits(4, LE), nonce(4, LE)]
const versionBuf = intToLE(0x20000000, 4);
const prevBlockHashBuf = Buffer.from('0000aaaa00000000000000000000000000000000000000000000000000000000', 'hex').reverse();
const merkleRootBuf = Buffer.from(blockMerkleRootHex, 'hex').reverse();
const timestampBuf = intToLE(Math.floor(Date.now() / 1000), 4);
const bitsBuf = intToLE(0x1f00ffff, 4);

let nonce = 0;
const difficultyTarget = BigInt('0x' + DIFFICULTY_TARGET_HEX);
let headerBuf, headerHash;
while (true) {
  const nonceBuf = intToLE(nonce, 4);
  headerBuf = Buffer.concat([versionBuf, prevBlockHashBuf, merkleRootBuf, timestampBuf, bitsBuf, nonceBuf]);
  headerHash = doubleSha256(headerBuf);
  const displayedHash = Buffer.from(headerHash).reverse();
  const hashInt = BigInt('0x' + displayedHash.toString('hex'));
  if (hashInt < difficultyTarget) break;
  nonce++;
}
const blockHeaderHex = headerBuf.toString('hex');

//------------------------------------------------------------------
// 8. Write out.txt
//------------------------------------------------------------------
const outLines = [];
outLines.push(blockHeaderHex);
outLines.push(coinbaseTx.toHex());
outLines.push(coinbaseTxidFinal);
selectedTxs.forEach(tx => outLines.push(tx.txid));
fs.writeFileSync('out.txt', outLines.join('\n'));

console.log('Block mined and out.txt generated successfully.');
