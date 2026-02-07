<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="Status">
  <img src="https://img.shields.io/badge/rust-1.70+-blue" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/p2p-libp2p-purple" alt="P2P">
</p>

<h1 align="center">⚡ Zero Protocol</h1>

<p align="center">
  <strong>The Signal of Email — Serverless, Encrypted, Unstoppable</strong>
</p>

<p align="center">
  Zero Protocol is a next-generation P2P email system with Signal-level security.<br>
  No servers. No providers. Your keys, your data, your identity.
</p>

---

## 🎯 What is Zero Protocol?

Zero Protocol is a **fully decentralized email system** built on modern P2P technology. Unlike traditional email where servers control your data, Zero Protocol ensures:

- **You own your identity** — Generated from a 12-word mnemonic (like Bitcoin)
- **You own your data** — Stored locally, encrypted with keys only you control
- **You own your privacy** — No servers to subpoena, no metadata to collect

```
Traditional Email:  You → Server → Recipient
Zero Protocol:      You ←→ P2P Mesh ←→ Recipient
```

---

## ✨ Features

### 🔐 Signal-Level Security
| Feature | Zero Protocol | Gmail | ProtonMail |
|---------|--------------|-------|------------|
| End-to-End Encryption | ✅ | ❌ | ✅ |
| Forward Secrecy | ✅ | ❌ | ❌ |
| Zero-Knowledge | ✅ | ❌ | ⚠️ |
| No Server Access | ✅ | ❌ | ❌ |

### 🆔 Decentralized Identity
- **Public Key as Address** — No central registry
- **Aliases** — Map "alice@zero" to public key via DHT
- **ENS Support** — Ready for blockchain identity integration

### 🌐 True P2P Architecture
- **Gossipsub Mesh** — Real-time message propagation
- **Kademlia DHT** — Decentralized peer discovery
- **DHT Mailbox** — Offline message delivery without servers
- **DNS Bootstrap** — Decentralized network joining

### 🛡️ Spam Prevention
- **Proof-of-Work (Hashcash)** — Computational cost to send
- **Reputation System** — Bad actors get banned instantly

### 🔋 Battery Optimization
| Mode | Heartbeat | Use Case |
|------|-----------|----------|
| FullNode | 10s | Desktop, plugged in |
| LightClient | 5 min | Laptop on battery |
| Standby | 10 min | App minimized |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Zero Protocol                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Crypto    │  │    P2P      │  │   Storage   │         │
│  │             │  │             │  │             │         │
│  │ • AES-256   │  │ • Gossipsub │  │ • SQLite    │         │
│  │ • Ed25519   │  │ • Kademlia  │  │ • Encrypted │         │
│  │ • ECIES     │  │ • mDNS      │  │             │         │
│  │ • Ratchet   │  │ • DHT Mail  │  │             │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                      libp2p + tokio                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔑 How It Works

### 1. Identity Creation
```rust
// Generate 12-word mnemonic (BIP39)
let mnemonic = crypto::generate_mnemonic()?;
// "abandon ability able about above absent..."

// Derive keys from mnemonic
let seed = crypto::derive_seed_from_mnemonic(&mnemonic, "")?;
let signing_key = crypto::derive_signing_key(&seed);

// Create Zero Address (Public Key)
let address = identity::ZeroAddress::from_public_key(signing_key.public);
println!("Your Address: {}", address);
```

### 2. Sending a Message
```
1. Encrypt message with recipient's public key
2. Apply Proof-of-Work (spam prevention)
3. Broadcast to Gossipsub mesh
4. If offline → Store in DHT Mailbox
```

### 3. Receiving a Message
```
1. Subscribe to your topic on Gossipsub
2. Check DHT Mailbox for offline messages
3. Decrypt with your private key
4. Verify sender's signature
```

### 4. Forward Secrecy (Symmetric Ratchet)
```rust
let mut ratchet = SymmetricRatchet::new(&shared_secret);

// Each message uses a NEW key
let key1 = ratchet.step()?; // Message 1
let key2 = ratchet.step()?; // Message 2
// key1 ≠ key2 — Old keys can't decrypt new messages
```

---

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+
- Cargo

### Build
```bash
git clone https://github.com/Gaddam-Revanth/Zero-Protocol.git
cd Zero-Protocol
cargo build --release
```

### Run Tests
```bash
cargo test -p zero_protocol
```

### Example Usage
```rust
use zero_protocol::{crypto, p2p, storage};

// Create identity
let mnemonic = crypto::generate_mnemonic()?;
let seed = crypto::derive_seed_from_mnemonic(&mnemonic, "")?;

// Start P2P node
let keypair = libp2p::identity::Keypair::generate_ed25519();
let swarm = p2p::build_swarm(keypair, None).await?;

// Send encrypted message
let ciphertext = crypto::encrypt_aes_256_cbc(b"Hello!", &key)?;
```

---

## 📊 Comparison with Competitors

| Feature | Zero Protocol | Bitmessage | Eppie | ProtonMail |
|---------|--------------|------------|-------|------------|
| Serverless | ✅ | ✅ | ⏳ WIP | ❌ |
| Identity | ✅ PubKey + Alias | ✅ PubKey | ✅ PubKey | ❌ Email |
| Forward Secrecy | ✅ | ❌ | ❌ | ❌ |
| Real-time | ✅ | ❌ | ⏳ WIP | ✅ |
| Spam Prevention | ✅ PoW+Rep | ✅ PoW | ❌ | ✅ |
| Battery Modes | ✅ | ❌ | ❌ | N/A |
| Offline Delivery | ✅ DHT | ✅ | ⏳ | ✅ |

---

## 🧪 Test Coverage

```
✅ Cryptography: AES-256, Ed25519, ECIES, BIP39, Argon2
✅ Forward Secrecy: Symmetric Ratchet key rotation
✅ P2P Networking: Gossipsub, Kademlia, mDNS
✅ Offline Delivery: DHT Mailbox (50 slots)
✅ Spam Prevention: PoW mining/verification
✅ Security: Replay attack mitigation, MITM prevention
✅ Battery: Power mode configuration

Total: 27+ tests passing
```

---

## 📁 Project Structure

```
zero_protocol/
├── src/
│   ├── lib.rs        # Module exports
│   ├── crypto.rs     # AES, Ed25519, ECIES, BIP39
│   ├── p2p.rs        # Gossipsub, Kademlia, DHT Mailbox
│   ├── ratchet.rs    # Symmetric Ratchet (Forward Secrecy)
│   ├── pow.rs        # Proof-of-Work (Hashcash)
│   ├── storage.rs    # SQLite encrypted storage
│   └── models.rs     # Data structures
└── tests/
    ├── protocol_comparison.rs  # vs Bitmessage, Eppie
    ├── security_scenarios.rs   # Replay, MITM tests
    └── ...
```

---

## 🛣️ Roadmap

- [x] **Phase 1**: Core Crypto (AES, Ed25519, BIP39)
- [x] **Phase 2**: P2P Layer (Gossipsub, Kademlia)
- [x] **Phase 3**: Spam Prevention (PoW, Reputation)
- [x] **Phase 4**: Offline Delivery (DHT Mailbox)
- [x] **Phase 5**: Battery Optimization (Power Modes)
- [ ] **Phase 6**: Desktop App (Tauri)
- [ ] **Phase 7**: Mobile App

---

## 🔒 Security

Zero Protocol is designed with security-first principles:

1. **No Trust Required** — Cryptographic proofs, not server trust
2. **Forward Secrecy** — Compromised keys can't decrypt past messages
3. **Zero-Knowledge** — Even network nodes can't read your data
4. **Anti-Spam** — Economic cost (PoW) + behavioral analysis (Reputation)

### Threat Model
| Attack | Mitigation |
|--------|------------|
| MITM | Noise protocol + Ed25519 signatures |
| Replay | Timestamps + PoW nonces |
| Spam | Hashcash PoW + Peer scoring |
| Key Compromise | Symmetric Ratchet (forward secrecy) |
| Traffic Analysis | Gossipsub mesh (no direct connections) |

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Submit a pull request

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---

<p align="center">
  <strong>Zero Protocol — Because email should belong to you.</strong>
</p>

<p align="center">
  🇮🇳 <em>Made in India for the World</em> 🌍
</p>
