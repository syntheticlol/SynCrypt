<div align="center">
  <h1>SynCrypt</h1>
  <p><em>Polymorphic encryption & obfuscation for red/blue team research</em></p>
  <img src="https://img.shields.io/badge/Polymorphic-Encryption-blueviolet?style=for-the-badge" alt="Polymorphic Encryption"/>
  <img src="https://img.shields.io/badge/Junk%20Masked-Output-orange?style=for-the-badge" alt="Junk Masked Output"/>
  <img src="https://img.shields.io/badge/Red%20%26%20Blue%20Team-Research-green?style=for-the-badge" alt="Red & Blue Team"/>
</div>

---

## ✨ Features
- **Polymorphic Output:** Each encryption is unique using random seeds & encoding.  
- **Junk Masking:** Random characters obfuscate the ciphertext to evade simple detection.  
- **Multiple Encodings:** Supports 5 unpredictable formats (`synxxxx`, `sxxyxxn`, etc.).  
- **Compact Header:** Only 48 bytes (32-byte seed + 16-byte nonce).  
- **256-bit Symmetric Key** for encryption/decryption.  
- **CLI Interface:** Easy to encrypt/decrypt messages.  
- **File Output:** Results saved to `enc.log` for convenience.

---

## ⚙ How It Works
1. Random seed + nonce generated per encryption.  
2. Plaintext encrypted using a custom S-box + encoding map.  
3. Junk characters inserted after every 2 real characters.  
4. Decryption reverses the masking & restores original text.

---

## 🚀 Quick Start

```bash
# Build
gcc -o syncrypt.exe encrypt.c syncrypt.c

# Run
./syncrypt.exe
```

### Example: Encrypting EICAR Test String

**Header (paste for decryption):**
```
b3Z12n4dIc8m43kbbk8baa6s1fv03w5as7dr09e38n25Z1fK5dyd4CcbxfcF96xf5T45L3bS13g0dy89p0aS1cFdbaaed32p20o9ao50eeeF40x78Z36Bfdc12O49e32Jf6U9ev7dP49vdca
```

**Encrypted:**
```
sybn0o19y4sGynp00o14esyyn0L07f4sPynB02N26Psyln0j17V2sRynV00i68psyYn0a10m7syyne00h90wsyQn0n05q5srynq00P35Msyxn0U02j1s...
```
> (truncated for readability)

**Decrypted Result:**
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

---

## 🎯 Use Cases
- **Red Team:** Payload staging, C2 obfuscation, loader beacons, bypass naive DLP/IDS.  
- **Blue Team:** Detection research, reverse engineering, forensic analysis.  
- **Research:** Demonstrates limits of pattern-based & entropy detection.

---

## 🔍 Detection Notes
- Junk-masked + polymorphic output evades simple regex/YARA detection.  
- Header + key are required to decode; decryption impossible without them.  
- Forensics: repeated 2 real + 1 junk character patterns can be tracked.

---

## 📌 Future Goals
- Support **binary/file encryption**.  
- Integrate with **C2 frameworks** (Cobalt Strike, Mythic, Merlin).  
- Add **adaptive junk patterns** for better evasion.  
- Provide **Python/PowerShell wrappers**.  
- GUI or web-based frontend.  
- Streaming encryption for **large files**.  
- Peer review & detection/cryptanalysis testing.

---

## ⚖ License & Disclaimer
MIT License. **For research, red/blue team development only.** Not intended for sensitive production data.

---

<div align="center">
  <em>SynCrypt – polymorphic encryption made simple & flexible for research purposes.</em>
</div>
