const fs = require('fs');
const path = require('path');
const { Transaction } = require('bitcoinjs-lib');
const crypto = require('crypto');

// Constants from BIP-141
const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0);
const TARGET = Buffer.from('0000ffff00000000000000000000000000000000000000000000000000000000', 'hex');
const MAX_BLOCK_WEIGHT = 4000000;

// Helper function to reverse byte order
function reverseHash(hash) {
    return Buffer.from(hash, 'hex').reverse().toString('hex');
}

// Calculate wtxid with proper endianness
function calculateWTXID(txHex) {
    const hash = crypto.createHash('sha256').update(
        crypto.createHash('sha256').update(Buffer.from(txHex, 'hex')).digest()
    );
    return reverseHash(hash.toString('hex'));
}

// Generate Merkle root from list of txids/wtxids
function generateMerkleRoot(items) {
    if (items.length === 0) return Buffer.alloc(32, 0);
    
    let level = items.map(item => Buffer.from(reverseHash(item), 'hex'));
    
    while (level.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            const right = (i + 1 < level.length) ? level[i + 1] : left;
            const concat = Buffer.concat([left, right]);
            const hash = crypto.createHash('sha256').update(
                crypto.createHash('sha256').update(concat)).digest();
            nextLevel.push(hash);
        }
        level = nextLevel;
    }
    return reverseHash(level[0].toString('hex'));
}

async function main() {
    // Load mempool transactions
    const mempoolDir = path.join(__dirname, 'mempool');
    const txs = fs.readdirSync(mempoolDir).map(file => {
        const data = JSON.parse(fs.readFileSync(path.join(mempoolDir, file), 'utf8'));
        return {
            txid: reverseHash(data.txid),
            wtxid: calculateWTXID(data.hex),
            weight: data.weight,
            hex: data.hex
        };
    });

    // Create coinbase transaction
    const coinbaseTx = new Transaction();
    coinbaseTx.version = 1;
    
    // Add coinbase input with witness reserved value
    coinbaseTx.addInput(Buffer.alloc(32, 0), 0xffffffff, 0xffffffff, Buffer.from('0000', 'hex'));
    coinbaseTx.ins[0].witness = [WITNESS_RESERVED_VALUE];
    
    // Add temporary output (will replace later)
    coinbaseTx.addOutput(Buffer.from('6a24aa21a9ed', 'hex'), 0);

    // Calculate initial coinbase weight
    const coinbaseWTXID = calculateWTXID(coinbaseTx.toHex());

    // Select transactions
    let totalWeight = coinbaseTx.weight();
    const selectedTxs = [];
    for (const tx of txs.sort((a, b) => b.fee - a.fee)) {
        if (totalWeight + tx.weight > MAX_BLOCK_WEIGHT) break;
        selectedTxs.push(tx);
        totalWeight += tx.weight;
    }

    // Build wtxid list (coinbase first)
    const wtxids = [coinbaseWTXID, ...selectedTxs.map(tx => tx.wtxid)];

    // Generate witness commitment
    const witnessRoot = generateMerkleRoot(wtxids);
    const witnessCommitment = reverseHash(
        crypto.createHash('sha256').update(
            crypto.createHash('sha256').update(
                Buffer.from(witnessRoot + WITNESS_RESERVED_VALUE.toString('hex'), 'hex')
            ).digest()
        ).digest().toString('hex')
    );

    // Update coinbase transaction with commitment
    coinbaseTx.outs[1].script = Buffer.concat([
        Buffer.from('6a24aa21a9ed', 'hex'),
        Buffer.from(witnessCommitment, 'hex')
    ]);

    // Finalize coinbase details
    const finalCoinbaseHex = coinbaseTx.toHex();
    const finalCoinbaseWTXID = calculateWTXID(finalCoinbaseHex);
    wtxids[0] = finalCoinbaseWTXID;

    // Generate txid list (coinbase first)
    const txids = [
        reverseHash(coinbaseTx.getHash().toString('hex')), 
        ...selectedTxs.map(tx => tx.txid)
    ];

    // Build block header
    const header = Buffer.alloc(80);
    header.writeUInt32LE(4, 0); // Version
    Buffer.from(reverseHash(TARGET.toString('hex')), 'hex').copy(header, 4); // Previous hash
    Buffer.from(generateMerkleRoot(txids), 'hex').copy(header, 36); // Merkle root
    header.writeUInt32LE(Math.floor(Date.now()/1000), 68); // Timestamp
    header.writeUInt32LE(0x1f00ffff, 72); // Bits
    
    // Mine block
    let nonce = 0;
    let hash;
    do {
        header.writeUInt32LE(nonce, 76);
        hash = crypto.createHash('sha256').update(
            crypto.createHash('sha256').update(header)).digest().reverse();
        nonce++;
    } while (hash.compare(TARGET) > 0 && nonce < 0xFFFFFFFF);

    // Write output
    fs.writeFileSync('out.txt', [
        header.toString('hex'),
        finalCoinbaseHex,
        ...txids.map(txid => reverseHash(txid)) // Convert back to little-endian
    ].join('\n'));
}

main().catch(console.error);