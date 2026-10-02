# multi-party-computation
# Privacy-Preserving Double Auction

This project implements a distributed **privacy-preserving double auction** in C++.

The system separates the auction into multiple parties so that bids are not handled by a single trusted process. Bidders split their values between two auctioneer parties (`P0` and `P1`), while `P2` assists with secure computation. `BidderBoss` manages commitment receipts and Merkle evidence, and `ProverParty` receives the final signed and encrypted dataset payloads produced by the auctioneers.

This README focuses on the C++ programs and their interaction.

---

## Components

| Program | Purpose |
|---|---|
| `bidder` | Creates secret shares of a bid and bidder ID, commitments, encrypted packets, proofs, and signatures. Sends data to `BidderBoss`, `P0`, and `P1`. |
| `bidderboss` | Collects bidder packets, signs receipts, builds Merkle trees, distributes Merkle evidence, publishes commitment roots, and later reveals commitment randomness. |
| `p0` | First auctioneer party. Decrypts its shares, verifies bidder data, filters invalid bidders, participates in secure sorting and clearing, and sends its final dataset payload to `ProverParty`. |
| `p1` | Second auctioneer party. Performs the same validation and MPC workflow for its own shares and coordinates with `P0`. |
| `p2` | Helper party for MPC. Generates random permutations, secret-shared auxiliary values, Beaver triples, and comparison shares used during sorting and clearing. |
| `prover_party` | Receives encrypted payloads from `P0/P1`, decrypts them, validates transport metadata, stores the received data, and returns an acknowledgement. |

---

## High-Level Architecture

```text
                         +------------------+
                         |    Blockchain    |
                         +--------^---------+
                                  |
                         roots / results /
                         dispute evidence
                                  |
                              BidderBoss
                           /      |       \
                          /       |        \
                         v        v         v
                     Bidder      P0 <----> P1
                       |          ^         ^
                       |          |         |
                       +--------> |         |
                                  \         /
                                   \       /
                                      P2
                              MPC helper party
                                   |
                                   v
                              ProverParty
```

The auction is divided into three main stages:

1. **Bid submission and validation**
2. **Secure sorting and auction clearing**
3. **Final dataset delivery to ProverParty**

---

## Protocol Flow

### 1. Bidder submission

A bidder is either a `buyer` or a `seller`.

For each bid, `bidder`:

- splits the bid value into additive shares for `P0` and `P1`;
- splits the bidder ID in the same way;
- creates commitments for the bid shares;
- encrypts the corresponding bid/ID share for each auctioneer;
- creates consistency proofs;
- signs the resulting packets.

The complete packet is first sent to `BidderBoss`.

The same signed party-specific packets are then sent directly to:

- `P0` on the buyer/seller P0 port;
- `P1` on the buyer/seller P1 port.

The bidder later receives its Merkle path from `BidderBoss` and checks that its commitment is included in the published tree.

---

### 2. BidderBoss

`BidderBoss` waits until the expected number of buyers and sellers has submitted.

It then builds four Merkle trees:

```text
Buyer  / P0
Buyer  / P1
Seller / P0
Seller / P1
```

For every bidder it creates signed receipt/evidence information and computes the corresponding Merkle path.

After all entries are collected, `BidderBoss`:

- computes the four Merkle roots;
- submits the roots for the current auction session;
- sends Merkle paths back to bidders;
- sends party-specific Merkle evidence to `P0` and `P1`;
- starts a reveal server used later by the auctioneers to obtain commitment randomness.

`BidderBoss` does **not** generate the bidder's secret shares or encrypted bid packets.

---

### 3. P0 and P1 validation

`P0` and `P1` receive bidder packets independently.

Each party:

- verifies the signed packet;
- decrypts its own bid share and ID share;
- checks the commitment/proof information;
- checks the Merkle evidence received from `BidderBoss`;
- keeps only bidders that pass validation.

The remaining bidders are stored as the valid bidder set.

Before MPC begins, `P0` and `P1` exchange bidder names and align their local data to the same canonical set and order.

If the number of valid buyers and sellers is zero or unequal, the current implementation ends the auction as **no trade** and skips the MPC stage.

---

## Secure Sorting

When the valid buyer and seller counts are equal and non-zero, the MPC stage starts.

The required ordering is:

```text
buyers  -> descending bid order
sellers -> ascending ask order
```

`P0` and `P1` hold only shares of the values.

`P2` assists the computation by generating:

- a random permutation;
- a secret-shared permutation matrix;
- random auxiliary vectors and matrices;
- Beaver multiplication triples;
- secret-shared comparison results.

The sorting protocol therefore operates on distributed shares rather than reconstructing all bids inside one auctioneer process.

---

## Auction Clearing

After sorting, `P0`, `P1`, and `P2` execute the clearing stage.

The auctioneers determine:

- the clearing position `K`;
- buyer-side clearing price `Pb`;
- seller-side clearing price `Ps`;
- winning buyer IDs;
- winning seller IDs.

`P2` supplies additional Beaver triples and comparison shares required for this stage.

The final result can then be submitted by `P0` and `P1` to the configured registry.

---

## Randomness Reveal

After the auction result is known, `P0` and `P1` contact the `BidderBoss` reveal server.

The auctioneers obtain the commitment randomness corresponding to their validated bidders and combine it with their local share data.

This produces the signed dataset information that is later delivered to `ProverParty`.

---

## ProverParty

`prover_party` is the C++ receiver for the final auctioneer payloads.

It listens for encrypted payloads from `P0` and `P1`.

For each connection it:

1. receives one length-prefixed encrypted JSON payload;
2. decrypts it with the ProverParty private key;
3. compares transport metadata with the decrypted payload;
4. validates `party_id`, `session_id`, `dataset_kind`, and sender consistency;
5. stores the encrypted transport and decrypted signed payload;
6. stores the auctioneer dataset/reveal information;
7. updates the canonical per-party data file;
8. returns a JSON acknowledgement to the sender.

The default listener is:

```text
0.0.0.0:7800
```

The main ProverParty key is:

```text
keys/ProverParty.elg.priv
```

The canonical output files are:

```text
zk-snark/sended_p0data.json
zk-snark/sended_p1data.json
```

Dataset-specific payloads are stored under:

```text
zk-snark/perm_payloads/
```

---

## Default Network Ports

| Port | Connection |
|---:|---|
| `7500` | Bidder -> BidderBoss |
| `7000` | Buyer -> P0 |
| `7001` | Buyer -> P1 |
| `7002` | Seller -> P0 |
| `7003` | Seller -> P1 |
| `6000` | P1 -> P0 |
| `6001` | P2 -> P0 |
| `6002` | P2 -> P1 |
| `7700` | P0/P1 -> BidderBoss randomness reveal |
| `7800` | P0/P1 -> ProverParty |

`P2` currently connects to `127.0.0.1:6001` and `127.0.0.1:6002`.

---

## Build

The source files provided with this version can be compiled as follows:

```bash
g++ -O2 -std=c++17 "bidder(20261002-210625).cpp" \
  -lcrypto -o bidder

g++ -O2 -std=c++17 "bidderboss(10).cpp" \
  -lcrypto -o bidderboss

g++ -O2 -std=c++17 "p0(20261002-210626).cpp" \
  -lcrypto -pthread -o p0

g++ -O2 -std=c++17 "p1(20261002-210626).cpp" \
  -lcrypto -pthread -o p1

g++ -O2 -std=c++17 "p2(20261002-210626).cpp" \
  -o p2

g++ -O2 -std=c++17 prover_party.cpp \
  -lcrypto -o prover_party
```

The six commands above were checked against the provided source files.

For a cleaner repository, the timestamped source files can be renamed to:

```text
bidder.cpp
bidderboss.cpp
p0.cpp
p1.cpp
p2.cpp
prover_party.cpp
```

---

## Typical Execution Order

A practical startup order is:

```text
1. ProverParty
2. P0
3. P1
4. BidderBoss
5. All buyer/seller bidder processes
6. P2
```

`P2` should be started after `P0` and `P1` reach the MPC stage and open ports `6001` and `6002`.

---

## Example: Start ProverParty

```bash
./prover_party \
  --listen 7800 \
  --priv keys/ProverParty.elg.priv \
  --out-dir zk-snark/perm_payloads
```

Useful ProverParty options include:

```text
--listen PORT
--priv PATH
--out-dir PATH
--sended-dir PATH
--max-n N
--once
```

`--once` makes the server stop after processing one connection.

---

## Example: Start P0

```bash
./p0 \
  --buyers \
  --sellers \
  --nbuyers 2 \
  --nsellers 2 \
  --perm-session-id 0 \
  --prover-host 127.0.0.1 \
  --prover-port 7800
```

Important defaults include:

```text
P0 private share key:  keys/p0.elg.priv
P0 -> P1 listener:     6000
P0 -> P2 listener:     6001
Boss reveal port:      7700
ProverParty port:      7800
```

---

## Example: Start P1

```bash
./p1 \
  --buyers \
  --sellers \
  --nbuyers 2 \
  --nsellers 2 \
  --p0 127.0.0.1 \
  --perm-session-id 0 \
  --prover-host 127.0.0.1 \
  --prover-port 7800
```

Important defaults include:

```text
P1 private share key:  keys/p1.elg.priv
P1 -> P0:              127.0.0.1:6000
P1 -> P2 listener:     6002
Boss reveal port:      7700
ProverParty port:      7800
```

---

## Example: Start BidderBoss

```bash
./bidderboss \
  --mode run \
  --nbuyers 2 \
  --nsellers 2 \
  --listen 7500 \
  --session-id 0 \
  --p0 127.0.0.1 \
  --p1 127.0.0.1 \
  --chain-rpc http://127.0.0.1:8545 \
  --auction-registry <REGISTRY_ADDRESS> \
  --eth-priv keys/bidderboss.eth.priv
```

The configured `--nbuyers` and `--nsellers` values must match the number of bidder processes expected for that session.

---

## Example: Submit a Buyer

```bash
./bidder \
  --mode submit \
  --boss 127.0.0.1 \
  --port 7500 \
  --session-id 0 \
  --role buyer \
  --name Alice \
  --bid 90 \
  --id 101 \
  --chain-rpc http://127.0.0.1:8545 \
  --auction-registry <REGISTRY_ADDRESS> \
  --eth-priv keys/Alice.eth.priv \
  --out receipts/Alice_receipt.json
```

A seller uses the same program with:

```text
--role seller
```

and its own ask value, ID, name, and key.

---

## Start P2

Once both auctioneers are ready for the MPC phase:

```bash
./p2
```

`P2` has no command-line configuration in the current implementation.

---

## Main Output Files

Typical files produced by the C++ pipeline include:

```text
receipts/*.json

onchain/commitment_metadata_session*.json
onchain/merkle_path_*.json
onchain/p0_revealed_randomness.json
onchain/p1_revealed_randomness.json

zk-snark/circuits/circomlib/sharebids_p0.json
zk-snark/circuits/circomlib/sharebids_p1.json

zk-snark/perm_payloads/*
zk-snark/sended_p0data.json
zk-snark/sended_p1data.json
```

The exact set depends on the enabled protocol stages and command-line options.

---

## Data Ownership Summary

A useful way to understand the design is by looking at which process owns which information:

| Party | Main information |
|---|---|
| Bidder | Original bid/ask and bidder ID |
| BidderBoss | Commitments, receipt/Merkle metadata, commitment randomness |
| P0 | P0 bid/ID shares and its local MPC state |
| P1 | P1 bid/ID shares and its local MPC state |
| P2 | Random MPC preprocessing data and temporary comparison information |
| ProverParty | Final encrypted/decrypted signed auctioneer dataset payloads |

The protocol is designed so that the original bid is not simply sent in plaintext to one central auctioneer component.

---

## Notes

- All components participating in the same auction must use the same session ID.
- `P0` and `P1` must agree on the final valid bidder set before MPC starts.
- The current protocol expects equal non-zero valid buyer and seller counts before entering the sorting/clearing stage.
- `BidderBoss` must receive all expected bidders before the Merkle trees are finalized.
- `ProverParty` should be running before `P0/P1` attempt to send their final payloads.
- The repository also contains external helper logic used by some cryptographic and blockchain operations. Those helpers are intentionally outside the scope of this C++-focused README.
- The implementation contains testing and dispute paths for intentionally malformed data; these are mainly intended for protocol and fault-handling experiments.

---

## End-to-End Summary

```text
Bidder
  |
  | split + commit + encrypt + sign
  v
BidderBoss -----------------------+
  |                               |
  | receipts + Merkle evidence    |
  v                               v
 P0 <---------------------------> P1
  \                               /
   \                             /
    +------------ P2 -----------+
          secure sorting
          secure clearing
                 |
                 v
       final auction result
                 |
       randomness from Boss
                 |
       signed/encrypted datasets
                 |
                 v
            ProverParty
```

In short, the project combines **secret sharing, cryptographic validation, Merkle-based commitment evidence, multi-party computation, and a separate prover-data receiver** to implement a distributed double-auction workflow.
