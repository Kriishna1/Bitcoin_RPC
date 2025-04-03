
## Overview
In this challenge, you are tasked with the simulation of mining process of a block, which includes validating and including transactions from a given set of transactions.
The repository contains a folder `mempool` which contains JSON files.
These files represent individual transactions. Your goal is to successfully mine a block by including some of these transactions, following the specific requirements outlined below.

## Objective
Your primary objective is to write a script that processes a series of transactions, validates them, and then mines them into a block. The output of your script should be a file named `out.txt` that follows a specific format.

Place your solution in the appropriate directory based on your chosen language:
- [bash](./bash/solution.sh)
- [javascript](./javascript/index.js)
- [python](./python/main.py)
- [rust](./rust/src/main.rs)

## Requirements
### Input
- You are provided with a folder named `mempool` containing several JSON files. Each file represents a transaction that includes all necessary information regarding the transaction.

### Output
Your script must generate an output file named `out.txt` with the following structure:
- First line: The block header.
- Second line: The serialized coinbase transaction.
- Following lines: The transaction IDs (txids) of the transactions mined in the block, in order. The first txid should be that of the coinbase transaction

### Difficulty Target
The difficulty target is `0000ffff00000000000000000000000000000000000000000000000000000000`. This is the value that the block hash must be less than for the block to be successfully mined.

### Previous Block Hash
You can use any value for the previous block hash as long as it meets the difficulty target.

## Execution
To test your solution locally:
- Uncomment the line corresponding to your language in [run.sh](./run.sh).
- Execute [`local.sh`](./local.sh).



