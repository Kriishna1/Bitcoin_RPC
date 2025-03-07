const fs = require('fs');
const path = require('path');
const { Transaction } = require('bitcoinjs-lib');
const crypto = require('crypto');

const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0);
const TARGET = Buffer.from('0000ffff00000000000000000000000000000000000000000000000000000000', 'hex');
const MAX_BLOCK_WEIGHT = 4000000;

function computeWtxid(txHex) {
    const tx = Transaction.fromHex(txHex);
    return tx.getHash(true).reverse().toString('hex');
}

function generateMerkleRoot(txids) {
    if (txids.length === 0) return null;

    let level = txids.map(txid => Buffer.from(txid, 'hex'));

    while (level.length > 1) {
        const nextLevel = [];
        for (let i = 0; i < level.length; i += 2) {
            const left = level[i];
            const right = (i + 1 < level.length) ? level[i + 1] : left;
            const pair = Buffer.concat([left, right]);
            const hash = crypto.createHash('sha256').update(pair).digest();
            nextLevel.push(hash);
        }
        level = nextLevel;
    }

    return level[0].toString('hex');
}

function calculateWitnessCommitment(witnessRoot) {
    const combined = Buffer.concat([
        Buffer.from(witnessRoot, 'hex'),
        WITNESS_RESERVED_VALUE
    ]);
    return crypto.createHash('sha256').update(combined).digest('hex');
}

async function main() {
    const mempoolDir = path.join(__dirname, 'mempool');
    const files = fs.readdirSync(mempoolDir);
    const transactions = [];

    // Load transactions from mempool
    for (const file of files) {
        const filePath = path.join(mempoolDir, file);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const tx = Transaction.fromHex(data.hex);
        const txid = tx.getHash().reverse().toString('hex');
        const wtxid = computeWtxid(data.hex);
        transactions.push({
            txid,
            wtxid,
            weight: data.weight,
            hex: data.hex,
        });
    }

    // Create coinbase transaction
    const coinbaseTx = new Transaction();
    coinbaseTx.version = 1;

    // Add coinbase input
    const scriptSig = Buffer.from('0000', 'hex'); // Minimal scriptSig
    coinbaseTx.addInput(Buffer.alloc(32, 0), 0xffffffff, 0xffffffff, scriptSig);
    coinbaseTx.ins[0].witness = [WITNESS_RESERVED_VALUE];

    // Add temporary output for witness commitment (to calculate weight)
    coinbaseTx.addOutput(Buffer.from('6a24aa21a9ed', 'hex'), 0);

    // Compute coinbase weight
    const coinbaseHex = coinbaseTx.toHex();
    const coinbaseTxObj = Transaction.fromHex(coinbaseHex);
    const coinbaseWeight = coinbaseTxObj.weight();

    // Select transactions
    let totalWeight = coinbaseWeight;
    const selectedTxs = [];
    for (const tx of transactions) {
        if (totalWeight + tx.weight > MAX_BLOCK_WEIGHT) break;
        selectedTxs.push(tx);
        totalWeight += tx.weight;
    }

    // Collect wtxids
    const coinbaseWtxid = computeWtxid(coinbaseHex);
    const wtxids = [coinbaseWtxid, ...selectedTxs.map(tx => tx.wtxid)];

    // Compute witness root and commitment
    const witnessRoot = generateMerkleRoot(wtxids);
    const witnessCommitment = calculateWitnessCommitment(witnessRoot);

    // Add witness commitment to coinbase transaction
    const witnessCommitmentScript = Buffer.concat([
        Buffer.from('6a24aa21a9ed', 'hex'),
        Buffer.from(witnessCommitment, 'hex')
    ]);
    coinbaseTx.outs[1].script = witnessCommitmentScript;

    // Finalize coinbase transaction
    const finalCoinbaseHex = coinbaseTx.toHex();
    const finalCoinbaseTx = Transaction.fromHex(finalCoinbaseHex);
    const coinbaseTxid = finalCoinbaseTx.getHash().reverse().toString('hex');

    // Generate txids for the block
    const txidsInBlock = [coinbaseTxid, ...selectedTxs.map(tx => tx.txid)];

    // Compute merkle root
    const merkleRootBE = generateMerkleRoot(txidsInBlock);
    const merkleRoot = Buffer.from(merkleRootBE, 'hex').reverse();

    // Build header
    const header = Buffer.alloc(80);
    header.writeUInt32LE(4, 0); // Version
    Buffer.alloc(32, 0).copy(header, 4); // Previous block hash
    merkleRoot.copy(header, 36);
    const timestamp = Math.floor(Date.now() / 1000);
    header.writeUInt32LE(timestamp, 68);
    header.writeUInt32LE(0x1f00ffff, 72); // Bits

    // Mine the block
    let nonce = 0;
    let hash;
    do {
        header.writeUInt32LE(nonce, 76);
        const h1 = crypto.createHash('sha256').update(header).digest();
        hash = crypto.createHash('sha256').update(h1).digest();
        nonce++;
    } while (hash.compare(TARGET) > 0 && nonce < 0xFFFFFFFF);

    if (nonce >= 0xFFFFFFFF) {
        throw new Error('Nonce not found');
    }

    // Write output
    const output = [
        header.toString('hex'),
        finalCoinbaseHex,
        ...txidsInBlock
    ].join('\n');

    fs.writeFileSync('out.txt', output);
    console.log('Block mined successfully! Output written to out.txt');
}

main().catch(err => console.error(err));