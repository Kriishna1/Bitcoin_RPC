const fs = require('fs');
const path = require('path');
const { Transaction } = require('bitcoinjs-lib');
const crypto = require('crypto');

const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0);
const TARGET = Buffer.from('0000ffff00000000000000000000000000000000000000000000000000000000', 'hex');
const MAX_BLOCK_WEIGHT = 4000000;

// Helper functions
function doubleSha256(buffer) {
    return crypto.createHash('sha256').update(
        crypto.createHash('sha256').update(buffer).digest()
    ).digest();
}

function generateMerkleRoot(items) {
    if (items.length === 0) return Buffer.alloc(32, 0);
    
    let level = items.map(item => Buffer.from(item, 'hex'));
    
    while (level.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            const right = (i + 1 < level.length) ? level[i + 1] : left;
            nextLevel.push(doubleSha256(Buffer.concat([left, right])));
        }
        level = nextLevel;
    }
    return level[0];
}

// Main implementation
async function main() {
    // Load mempool transactions
    const mempoolDir = path.join(__dirname, 'mempool');
    const files = fs.readdirSync(mempoolDir);
    const txs = [];
    
    for (const file of files) {
        const data = JSON.parse(fs.readFileSync(path.join(mempoolDir, file), 'utf8'));
        const tx = Transaction.fromHex(data.hex);
        txs.push({
            txid: tx.getHash().reverse().toString('hex'),
            wtxid: tx.getHash(true).reverse().toString('hex'),
            weight: data.weight,
            hex: data.hex
        });
    }

    // Create coinbase transaction
    const coinbaseTx = new Transaction();
    coinbaseTx.version = 1;
    
    // Add coinbase input
    coinbaseTx.addInput(Buffer.alloc(32, 0), 0xffffffff, 0xffffffff, Buffer.from('0000', 'hex'));
    coinbaseTx.ins[0].witness = [WITNESS_RESERVED_VALUE];
    
    // Add temporary output (will replace later)
    coinbaseTx.addOutput(Buffer.from('6a24aa21a9ed', 'hex'), 0);

    // Select transactions
    let totalWeight = coinbaseTx.weight();
    const selectedTxs = [];
    for (const tx of txs.sort((a, b) => b.fee - a.fee)) {
        if (totalWeight + tx.weight > MAX_BLOCK_WEIGHT) break;
        selectedTxs.push(tx);
        totalWeight += tx.weight;
    }

    // Prepare wtxids (coinbase first)
    const coinbaseWTxid = coinbaseTx.getHash(true).reverse().toString('hex');
    const wtxids = [coinbaseWTxid, ...selectedTxs.map(tx => tx.wtxid)];
    
    // Prepare txids (coinbase first)
    const txids = [coinbaseTx.getHash().reverse().toString('hex'), ...selectedTxs.map(tx => tx.txid)];

    // Compute witness commitment
    const witnessRoot = generateMerkleRoot(wtxids);
    const witnessCommitment = doubleSha256(Buffer.concat([
        witnessRoot,
        WITNESS_RESERVED_VALUE
    ])).toString('hex');
    
    // Update coinbase with witness commitment
    coinbaseTx.outs[1].script = Buffer.concat([
        Buffer.from('6a24aa21a9ed', 'hex'),
        Buffer.from(witnessCommitment, 'hex')
    ]);
    
    // Recompute coinbase txid after modification
    const finalCoinbaseTxid = coinbaseTx.getHash().reverse().toString('hex');
    txids[0] = finalCoinbaseTxid;

    // Build block header
    const header = Buffer.alloc(80);
    header.writeUInt32LE(4, 0); // Version
    Buffer.alloc(32, 0).copy(header, 4); // Previous hash
    generateMerkleRoot(txids).copy(header, 36); // Merkle root
    header.writeUInt32LE(Math.floor(Date.now()/1000), 68); // Timestamp
    header.writeUInt32LE(0x1f00ffff, 72); // Bits
    
    // Mine block
    let nonce = 0;
    let hash;
    do {
        header.writeUInt32LE(nonce, 76);
        hash = doubleSha256(header);
        nonce++;
    } while (Buffer.compare(hash.reverse(), TARGET) > 0 && nonce < 0xFFFFFFFF);

    // Write output
    fs.writeFileSync('out.txt', [
        header.toString('hex'),
        coinbaseTx.toHex(),
        ...txids
    ].join('\n'));
}

main().catch(console.error);