<div align="center">
  <img src="https://img.shields.io/badge/Polymorphic-Encryption-blueviolet?style=for-the-badge" alt="Polymorphic Encryption"/>
  <img src="https://img.shields.io/badge/Junk%20Masked-Output-orange?style=for-the-badge" alt="Junk Masked Output"/>
  <img src="https://img.shields.io/badge/Red%20%26%20Blue%20Team-Research-green?style=for-the-badge" alt="Red & Blue Team"/>
</div>

# SynCrypt

> **Advanced Polymorphic Encryption & Obfuscation Tool**  
> _A modern, research-focused encryption tool for payload delivery, detection evasion, and security research._

---

## ✨ Features

- **Polymorphic Output:** Unique ciphertext for every encryption (random seed, nonce, encoding format)
- **Junk Masking:** Obfuscates output and headers with random alphanumeric junk
- **Multiple Encoding Formats:** Five unpredictable encoding patterns (e.g., `synxxxx`, `sxxyxxn`, ...)
- **Compact Header:** 32-byte seed + 16-byte nonce (masked)
- **Symmetric Key:** 32-byte (256-bit) key
- **CLI User Interface:** Interactive prompts for mode, key, and input
- **Output to File:** Encrypted results written to `enc.log`

---

## 📖 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Red Team Use Cases](#red-team-use-cases)
- [Blue Team/Detection Research](#blue-teamdetection-research)
- [Comparison to Other Encryption Schemes](#comparison-to-other-encryption-schemes)
- [Detection Evasion & Limitations](#detection-evasion--limitations)
- [YARA/Regex Detection Examples](#yararegex-detection-examples)
- [Research & Development Roadmap](#research--development-roadmap)
- [FAQ](#faq)
- [License & Disclaimer](#license--disclaimer)

---

## 📝 Overview

SynCrypt is a polymorphic encryption and obfuscation tool for red team payload delivery, C2 channel evasion, and blue team detection research. It combines custom block cipher logic, junk-masked output, and unpredictable encoding formats to defeat static, signature, and entropy-based detection.

---

## ⚙️ How It Works

1. **Seed & Nonce Generation:** Random 32-byte seed and 16-byte nonce for each encryption
2. **Junk Masking:** After every 2 real characters, 1 random alphanumeric junk character is inserted
3. **Multiple Encoding Formats:** Each byte is encoded using one of five unpredictable formats
4. **Encryption:** Plaintext is encrypted with a custom S-box and encoding map, then masked
5. **Decryption:** Header and ciphertext are unmasked, S-box and map are regenerated, and plaintext is recovered

---

syncrypt.exe

## 🚀 Quick Start

```sh
# Build
gcc -o syncrypt.exe syncrypt_tool.c syncrypt.c

# Run
syncrypt.exe
```


- **C2 Channels:** Obfuscated output can be tunneled through text-based protocols
- **Payload Staging:** Small, self-contained headers and output are ideal for staged payloads or loader beacons
- **Bypassing DLP/IDS:** Junk-masked output can bypass naive DLP/IDS rules
- **Chaining:** Combine with steganography, protocol tunneling, or other obfuscation for layered evasion


## 🔬 Blue Team/Detection Research

- **Detection Challenges:**
  - Junk-masked output breaks simple regex, YARA, and entropy-based rules
  - Polymorphic output means no two encryptions are alike
  - Multiple encoding formats defeat fixed-pattern matching
- **Detection Opportunities:**
  - Look for repeated patterns of alphanumeric junk (2 real, 1 junk)
  - Use statistical analysis to spot non-natural character distributions
- **Reverse Engineering:**
  - Blue teams can reconstruct the S-box/map if the seed+nonce and key are recovered
  - Junk removal is deterministic if the pattern is known (2 real, 1 junk)

---

## 📊 Comparison to Other Encryption Schemes

| Feature                | SynCrypt                | AES (CBC/CTR)         | RC4/ChaCha20           | XOR/Stream Ciphers     |
|------------------------|-------------------------|-----------------------|------------------------|------------------------|
| Key Size               | 256 bits (32 bytes)     | 128/192/256 bits      | 128/256 bits           | Any                    |
| Output Polymorphism    | High (junk, seed+nonce) | Low (IV/nonce only)   | Low (nonce only)       | None                   |
| Output Obfuscation     | Junk-masked, non-base64 | None (raw/base64)     | None (raw/base64)      | None                   |
| Detection Resistance   | High (junk, variable)   | Low                   | Low                    | Very Low               |
| Standardized           | No (custom)             | Yes                   | Yes                    | No                     |
| Performance            | Moderate                | High                  | High                   | Very High              |
| Cryptanalysis          | Not peer-reviewed       | Peer-reviewed         | Peer-reviewed          | Weak                   |

---

## 🕵️ Detection Evasion & Limitations

**Strengths:**
- Defeats static, signature, and entropy-based detection
- Polymorphic output and junk masking make pattern matching difficult
- Multiple encoding formats further complicate detection

**Limitations:**
- Not cryptographically secure for protecting sensitive data
- Behavioral and contextual analysis can still reveal usage
- If header and key are recovered, decryption is possible

---


## 🧑‍💻 YARA/Regex Detection Examples

**Regex for all formats:**

```regex
(syn[0-9]{4}|sxxyxxn[0-9]{4}|sxyxxnx[0-9]{4}|xsxyxnx[0-9]{4}|sxyxnxx[0-9]{4})
```

**YARA Rule Example:**

```yara
rule SynCrypt_EncodedPattern {
  strings:
    $f1 = /syn[0-9]{4}/
    $f2 = /sxxyxxn[0-9]{4}/
    $f3 = /sxyxxnx[0-9]{4}/
    $f4 = /xsxyxnx[0-9]{4}/
    $f5 = /sxyxnxx[0-9]{4}/
  condition:
    any of them
}
```

---
## 🛠️ Research & Development Roadmap

- [ ] Add support for file and binary payloads
- [ ] Add more junk patterns and adaptive masking
- [ ] Provide Python and PowerShell wrappers
- [ ] Peer review and cryptanalysis
---


## ❓ FAQ

**Q: Is SynCrypt cryptographically secure?**

> No. SynCrypt is designed for obfuscation, polymorphism, and red/blue team research, not for high-assurance cryptographic protection.

**Q: Can SynCrypt output be detected?**

> While junk masking and polymorphism defeat naive detection, advanced statistical or behavioral analysis can still reveal usage.

**Q: Can I use SynCrypt for file encryption?**

> SynCrypt is optimized for text and payloads. For large files, chunking and additional error handling are needed.

**Q: How do I change the junk pattern?**

> Edit the `mask_with_junk` and `unmask_junk` functions in the source code.

**Q: What if I lose the header or key?**

> Decryption is impossible without both the correct key and the exact header (seed+nonce).

---



## ⚖️ License & Disclaimer

MIT License. This tool is for research, red team, and blue team development only. Do not use for protecting sensitive data in production environments.

---



3. **Encryption:**

## Overview   - The plaintext is encrypted using a custom S-box and encoding map.

**SynCrypt** is a research-focused, polymorphic encryption and obfuscation tool designed for red team payload delivery, C2 channel evasion, and blue team detection research. It combines custom block cipher logic, junk-masked output, and multiple unpredictable encoding formats to defeat static, signature, and entropy-based detection.   - The result is encoded and masked with junk.

4. **Decryption:**

---   - The header and encrypted text are unmasked, the S-box and map are regenerated, and the original plaintext is recovered.



## Features---

- **Polymorphic Output:** Each encryption uses a random seed, nonce, and encoding format, producing unique ciphertext for the same input every time.

- **Junk Masking:** Encrypted output and headers are obfuscated with random alphanumeric junk, breaking simple pattern and entropy-based detection.# Table of Contents

- **Multiple Encoding Formats:** Supports five unpredictable encoding patterns (e.g., `synxxxx`, `sxxyxxn`, etc.), randomly chosen per byte.- [Overview](#syncrypt)

- **Compact Header:** Only a 32-byte seed and 16-byte nonce are stored (masked), keeping headers small and efficient.- [Features](#features)

- **Symmetric Key:** Uses a 32-byte (256-bit) key for encryption and decryption.- [How It Works](#how-it-works)
- **CLI User Interface:** Interactive prompts for mode, key, and input.- [Quick Start](#quick-start)

- **Output to File:** Encrypted results are written to `enc.log` for easy retrieval.- [Usage Examples](#usage-examples)
- [Comparison to Other Encryption Schemes](#comparison-to-other-encryption-schemes)
## How SynCrypt Works- [Red Team Use Cases](#red-team-use-cases)

1. **Seed & Nonce Generation:**- [Blue Team/Detection Research](#blue-teamdetection-research)

   - For each encryption, a random 32-byte seed and 16-byte nonce are generated.- [Advanced Customization](#advanced-customization)

   - The S-box and encoding map are deterministically derived from the seed+nonce.- [Troubleshooting](#troubleshooting)

2. **Junk Masking:**- [FAQ](#faq)

   - After every 2 real characters in the header and encrypted output, 1 random alphanumeric junk character is inserted.- [Professional Documentation Notes](#professional-documentation-notes)

   - During decryption, these junk characters are reliably filtered out.- [Disclaimer](#disclaimer)

3. **Multiple Encoding Formats:**- [License](#license)

   - Each encrypted byte is encoded using one of five unpredictable formats, e.g., `synxxxx`, `sxxyxxn`, `sxyxxnx`, `xsxyxnx`, `sxyxnxx`.- [Author](#author)

   - Decoder recognizes and parses all formats.

4. **Encryption:**---

   - The plaintext is encrypted using a custom S-box and encoding map.
   - The result is encoded and masked with junk.## Quick Start

5. **Decryption:**

   - The header and encrypted text are unmasked, the S-box and map are regenerated, and the original plaintext is recovered.1. **Build:**
   ```sh

---   gcc -o syncrypt.exe supercrypt_tool.c supercrypt.c

   

## Usage Scenarios2. **Run:**

- **Red Team:** Payload delivery, C2 channel obfuscation, loader beacons, staged payloads, bypassing DLP/IDS, and evading static/entropy-based detection.   ```sh

- **Blue Team:** Detection engineering, reverse engineering, forensic analysis, and research on advanced obfuscation and polymorphic encryption.   syncrypt.exe

- **Research:** Demonstrating the limits of static detection, entropy analysis, and the need for behavioral and contextual security controls.   ```

3. **Encrypt:**

---   - Select `enc` mode, generate or enter a key, input your plaintext.

   - Output is written to `enc.log`.

## Red Team Applications4. **Decrypt:**

- **Payload Evasion:** SynCrypt's polymorphic, junk-masked output can evade YARA, regex, and static pattern-based detection.   - Select `dec` mode, enter the key, paste the masked encrypted text and header from `enc.log`.

- **C2 Channels:** Obfuscated output can be tunneled through text-based protocols, blending with noisy traffic.

- **Payload Staging:** Small, self-contained headers and output are ideal for staged payloads or loader beacons.---

- **Bypassing DLP/IDS:** Junk-masked output can bypass naive DLP/IDS rules that expect base64 or hex.

- **Chaining:** Combine with steganography, protocol tunneling, or other obfuscation for layered evasion.## Usage Examples






### Encrypting a Message

```console
Select mode (enc/dec/help): enc
Generate random key? (y/n): n
Enter key (hex, 32 bytes): 7e8a9c2b1d4f5e6a8b7c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2
Enter text to encrypt: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
[+] Output written to enc.log
```

**Example Output:**

  Header:
  b3Z12n4dIc8m43kbbk8baa6s1fv03w5as7dr09e38n25Z1fK5dyd4CcbxfcF96xf5T45L3bS13g0dy89p0aS1cFdbaaed32p20o9ao50eeeF40x78Z36Bfdc12O49e32Jf6U9ev7dP49vdca

  Encrypted:
  sybn0o19y4sGynp00o14esyyn0L07f4sPynB02N26Psyln0j17V2sRynV00i68psyYn0a10m7syyne00h90wsyQn0n05q5srynq00P35Msyxn0U02j1sjynl02O25Osyvn0A13O5swynU01x25wsyHn0M03s9sNynC01B22XsyCn0O14k2ssynf01z79ksyVn0A01T0sXynd00K85Nsyln0y00J4sYynH01f01Isyxn0j19s3sWynn01k01ksyUn0F02N6suynX00x27Zsyrn0z14b6smynn01M01gsyqn0O15o1skyne01t83lsyyn0h13N1skynO01a52UsyGn0z22q0sRynC00D94DsyIn0U07T7seyni02o30jsywn0a00y4syynz00p72VsySn0c03M5spynS00a90jsyln0f13V7sgynU01B27fsyAn0A24O6svynl01Z78Ysyln0N17T2srynK01d86Csypn0w19S3sRynt01E15ssyJn0W03h8sdynI00Z44csyon0B15z4sCynN02F31wsyln0Q13i4sJynT00v01Dsywn0v12x8shynR02C21Bsyln0D13V1sgyny00l48wsyGn0b09u1sSynB02M39bsyOn0r00x6sTynl00h80csysn0M21p0sxyno01h05Gsymn0G08N8skynE01u28Fsydn0X05O2stynO00g02bsygn0X06p6sEyny02a14NsyFn0e10t3sCynu01k95esyPn0Z03S4sHynK01l02Jsyun0G10g3sGyne00k94jsydn0q07z6sJyne01N84psyen0v20Q8sgynx01i34Esypn0j19S1srynD00Z48jsyAn0z13U4sJynl02L27csyhn0h09B9sfynQ02m05Ksyin0M09w5szyno01B04isyWn0y01b5sxynD01U25Usynn0F17S6skynS00r34ssyrn0t10E7sKynm01q24DsyCn0y17Z5sjynE00e14U

- **Detection Opportunities:**

  - Look for repeated patterns of alphanumeric junk (e.g., 2 real, 1 junk) in traffic or files.### Decrypting a Message

  - Use statistical analysis to spot non-natural character distributions.```

  - Monitor for the presence of the tool or its CLI artifacts (e.g., `enc.log`).Select mode (enc/dec/help): dec

  - Develop YARA rules for the five encoding formats.Generate random key? (y/n): n

- **Reverse Engineering:**Enter key (hex, 32 bytes): <your-key-here>

  - If header and key are recovered, S-box and map can be reconstructed for forensic analysis.Enter encrypted text (synXXXX): <masked-encrypted-output>

  - Junk removal is deterministic if the pattern is known (2 real, 1 junk).Paste header from encryption output: <masked-header>

Decrypted: Attack at dawn!

---```


- SynCrypt is optimized for text and payloads. For large files, chunking and additional error handling are needed.

**Note:** SynCrypt is not a replacement for strong cryptography in high-assurance environments. It is a research tool for obfuscation and detection evasion.

**Q: How do I change the junk pattern?**

---- Edit the `mask_with_junk` and `unmask_junk` functions in the source code.



## Detection Evasion & Limitations**Q: What if I lose the header or key?**

- **Strengths:**- Decryption is impossible without both the correct key and the exact header (seed+nonce).

  - Defeats static, signature, and entropy-based detection.

  - Polymorphic output and junk masking make pattern matching difficult.---

  - Multiple encoding formats further complicate detection.

- **Limitations:**## Additional Red Team/Blue Team Research Notes

  - Not cryptographically secure for protecting sensitive data.

  - Behavioral and contextual analysis can still reveal usage.### Red Team

  - If header and key are recovered, decryption is possible.- **Bypass Techniques:**

  - Use SynCrypt to wrap payloads, C2 beacons, or loader stagers to evade static and entropy-based detection.

---  - Chain with other obfuscation (e.g., steganography, protocol tunneling) for layered evasion.

- **Operational Security:**

## YARA/Regex Detection Examples  - Rotate keys and never reuse headers between operations.

**Regex for all formats:**  - Use ephemeral keys for one-time payloads.

```

(syn[0-9]{4}|sxxyxxn[0-9]{4}|sxyxxnx[0-9]{4}|xsxyxnx[0-9]{4}|sxyxnxx[0-9]{4})### Blue Team

```- **Detection Engineering:**

  - Develop YARA rules for repeated alphanumeric patterns (2 real, 1 junk) or for the presence of `enc.log` artifacts.

**YARA Rule Example:**  - Use entropy and n-gram analysis to flag non-natural text blocks.

```yara  - Monitor for suspicious CLI activity or custom encryption binaries.

rule SynCrypt_EncodedPattern- **Reverse Engineering:**

{  - If header and key are recovered, S-box and map can be reconstructed for forensic analysis.

    strings:

        $f1 = /syn[0-9]{4}/---

        $f2 = /sxxyxxn[0-9]{4}/

        $f3 = /sxyxxnx[0-9]{4}/## Example YARA Rule for Detection

        $f4 = /xsxyxnx[0-9]{4}/```yara

        $f5 = /sxyxnxx[0-9]{4}/rule SynCrypt_JunkPattern

    condition:{

        any of them    strings:

}        $junk = /([A-Za-z0-9]{2}[A-Za-z0-9]){10,}/

```    condition:

        $junk

---}

```

## Research & Development Roadmap

- [ ] Add support for file and binary payloads---

- [ ] Integrate with C2 frameworks (e.g., Cobalt Strike, Mythic)

- [ ] Add more junk patterns and adaptive masking## Research & Development Roadmap

- [ ] Provide Python and PowerShell wrappers- [ ] Add support for file and binary payloads

- [ ] Peer review and cryptanalysis- [ ] Integrate with C2 frameworks (e.g., Cobalt Strike, Mythic)

- [ ] Add more junk patterns and adaptive masking

- [ ] Provide Python and PowerShell wrappers

- [ ] Peer review and cryptanalysis

## FAQ

**Q: Is SynCrypt cryptographically secure?**---

- No. SynCrypt is designed for obfuscation, polymorphism, and red/blue team research, not for high-assurance cryptographic protection.

## File Output

**Q: Can SynCrypt output be detected?**- `enc.log` contains:

- While junk masking and polymorphism defeat naive detection, advanced statistical or behavioral analysis can still reveal usage.  - Masked header (for decryption)

  - Masked encrypted output

**Q: Can I use SynCrypt for file encryption?**

- SynCrypt is optimized for text and payloads. For large files, chunking and additional error handling are needed.## Security Notes

- The tool uses a custom S-box and encoding map for each encryption, derived from a random seed and nonce.

**Q: How do I change the junk pattern?**- Junk masking is deterministic and symmetric, ensuring reliable decryption.

- Edit the `mask_with_junk` and `unmask_junk` functions in the source code.- Only alphanumeric characters are used for junk to guarantee safe filtering.

- The encryption is polymorphic: the same input and key will never produce the same output twice.

**Q: What if I lose the header or key?**

- Decryption is impossible without both the correct key and the exact header (seed+nonce).## Comparison to Other Encryption Schemes



---| Feature                | SynCrypt                | AES (CBC/CTR)         | RC4/ChaCha20           | XOR/Stream Ciphers     |

|------------------------|-------------------------|-----------------------|------------------------|------------------------|

## License & Disclaimer| Key Size               | 256 bits (32 bytes)     | 128/192/256 bits      | 128/256 bits           | Any                    |

MIT License. This tool is for research, red team, and blue team development only. Do not use for protecting sensitive data in production environments.| Header Size            | 48 bytes (masked)       | 16 bytes (IV)         | 8-12 bytes (nonce)     | None/Optional          |

| Output Polymorphism    | High (junk, seed+nonce) | Low (IV/nonce only)   | Low (nonce only)       | None                   |

---| Output Obfuscation     | Junk-masked, non-base64 | None (raw/base64)     | None (raw/base64)      | None                   |

| Detection Resistance   | High (junk, variable)   | Low                   | Low                    | Very Low               |

| Standardized           | No (custom)             | Yes                   | Yes                    | No                     |
| Performance            | Moderate                | High                  | High                   | Very High              |
| Cryptanalysis          | Not peer-reviewed       | Peer-reviewed         | Peer-reviewed          | Weak                   |

### Red Team Use Cases
- **Payload Evasion:** SynCrypt's polymorphic, junk-masked output can evade YARA, regex, and static pattern-based detection.
- **C2 Channels:** Obfuscated output can be tunneled through text-based protocols, blending with noisy traffic.
- **Payload Staging:** Small, self-contained headers and output are ideal for staged payloads or loader beacons.
- **Bypassing DLP/IDS:** Junk-masked output can bypass naive DLP/IDS rules that expect base64 or hex.

### Blue Team/Detection Research
- **Detection Challenges:**
  - Junk-masked output breaks simple regex, YARA, and entropy-based rules.
  - Polymorphic output means no two encryptions are alike, complicating hash- or signature-based detection.
- **Detection Opportunities:**
  - Look for repeated patterns of alphanumeric junk (e.g., 2 real, 1 junk) in traffic or files.
  - Use statistical analysis to spot non-natural character distributions.
  - Monitor for the presence of the tool or its CLI artifacts (e.g., `enc.log`).
- **Reverse Engineering:**
  - Blue teams can reconstruct the S-box/map if the seed+nonce and key are recovered.
  - Junk removal is deterministic if the pattern is known (2 real, 1 junk).

## Professional Documentation Notes
- **Red Team:** SynCrypt is ideal for research, payload delivery, and C2 obfuscation where custom, non-standard encryption is needed. It is not a replacement for strong cryptography in high-assurance environments.
- **Blue Team:** Focus on behavioral, statistical, and tool artifact detection. Consider instrumenting endpoints to monitor for custom CLI tools and junk-masked output patterns.
- **Research:** SynCrypt is a demonstration of how polymorphism and junk masking can defeat naive detection, but is not a substitute for cryptographically secure, peer-reviewed algorithms for data at rest or in transit.

## Disclaimer
This tool is for research, red team, and blue team development only. Do not use for protecting sensitive data in production environments.
