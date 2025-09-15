<div align="center">
  <img src="https://img.shields.io/badge/Polymorphic-Encryption-blueviolet?style=for-the-badge" alt="Polymorphic Encryption"/>
  <img src="https://img.shields.io/badge/Junk%20Masked-Output-orange?style=for-the-badge" alt="Junk Masked Output"/>
  <img src="https://img.shields.io/badge/Red%20%26%20Blue%20Team-Research-green?style=for-the-badge" alt="Red & Blue Team"/>
</div>

# SynCrypt  

> Polymorphic encryption and obfuscation tool for red/blue team research.

---

## Features
- **Polymorphic Output:** Every encryption is unique using random seeds and encoding.  
- **Junk Masking:** Inserts random characters to make detection harder.  
- **Multiple Encodings:** Supports five different formats (`synxxxx`, `sxxyxxn`, etc.).  
- **Compact Header:** Only 48 bytes (32-byte seed + 16-byte nonce).  
- **256-bit Symmetric Key** for encryption/decryption.  
- **CLI-Based:** Easy prompts for encrypting/decrypting text.  
- **Output to File:** Saves results to `enc.log`.

---

## How It Works
1. Random seed + nonce generation for each encryption.  
2. Custom S-box + encoding map applied to plaintext.  
3. Junk characters inserted in a repeatable pattern.  
4. Decryption removes junk, regenerates S-box, and restores plaintext.

---

## Quick Start

```sh
# Build
gcc -o syncrypt.exe encrypt.c syncrypt.c

# Run
syncrypt.exe
```

**Encrypting a Message:**
```console
Select mode (enc/dec/help): enc
Enter key (hex, 32 bytes): 7e8a9c2b1d4f5e6a8b7c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2
Output written to enc.log
```

**Example: EICAR Test File**  

Header (paste for decryption):  
```
b3Z12n4dIc8m43kbbk8baa6s1fv03w5as7dr09e38n25Z1fK5dyd4CcbxfcF96xf5T45L3bS13g0dy89p0aS1cFdbaaed32p20o9ao50eeeF40x78Z36Bfdc12O49e32Jf6U9ev7dP49vdca
```

Encrypted text (synXXXX):  
```
sybn0o19y4sGynp00o14esyyn0L07f4sPynB02N26Psyln0j17V2sRynV00i68psyYn0a10m7syyne00h90wsyQn0n05q5srynq00P35Msyxn0U02j1sjynl02O25Osyvn0A13O5swynU01x25wsyHn0M03s9sNynC01B22XsyCn0O14k2ssynf01z79ksyVn0A01T0sXynd00K85Nsyln0y00J4sYynH01f01Isyxn0j19s3sWynn01k01ksyUn0F02N6suynX00x27Zsyrn0z14b6smynn01M01gsyqn0O15o1skyne01t83lsyyn0h13N1skynO01a52UsyGn0z22q0sRynC00D94DsyIn0U07T7seyni02o30jsywn0a00y4syynz00p72VsySn0c03M5spynS00a90jsyln0f13V7sgynU01B27fsyAn0A24O6svynl01Z78Ysyln0N17T2srynK01d86Csypn0w19S3sRynt01E15ssyJn0W03h8sdynI00Z44csyon0B15z4sCynN02F31wsyln0Q13i4sJynT00v01Dsywn0v12x8shynR02C21Bsyln0D13V1sgyny00l48wsyGn0b09u1sSynB02M39bsyOn0r00x6sTynl00h80csysn0M21p0sxyno01h05Gsymn0G08N8skynE01u28Fsydn0X05O2stynO00g02bsygn0X06p6sEyny02a14NsyFn0e10t3sCynu01k95esyPn0Z03S4sHynK01l02Jsyun0G10g3sGyne00k94jsydn0q07z6sJyne01N84psyen0v20Q8sgynx01i34Esypn0j19S1srynD00Z48jsyAn0z13U4sJynl02L27csyhn0h09B9sfynQ02m05Ksyin0M09w5szyno01B04isyWn0y01b5sxynD01U25Usynn0F17S6skynS00r34ssyrn0t10E7sKynm01q24DsyCn0y17Z5sjynE00e14U
```

Decrypted result:  
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

---

## Use Cases
- **Red Team:** Payload staging, C2 obfuscation, loader beacons, bypass naive DLP/IDS.  
- **Blue Team:** Detection research, reverse engineering, forensic analysis.  
- **Research:** Test limits of pattern-based and entropy detection.

---

## Detection Notes
- Junk-masked + polymorphic output avoids simple regex/YARA detection.  
- Header + key required to decode; without them, decryption is impossible.  
- Look for repeated patterns (e.g., 2 real chars, 1 junk) for forensic analysis.

---

## Future Goals
- Add **binary/file encryption** support.  
- Integrate with **C2 frameworks** (Cobalt Strike, Mythic, Merlin).  
- More **adaptive junk patterns** to improve evasion.  
- Add **Python/PowerShell wrappers**.  
- GUI or web-based frontend for easier use.  
- Support **streaming encryption** for large files.  
- Peer review and testing for cryptanalysis and detection research.

---

## License & Disclaimer
MIT License. For **research, red/blue team development only**. Not intended for sensitive production data.
