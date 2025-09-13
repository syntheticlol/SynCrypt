#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "syncrypt.h"

#define MAX_TEXT 4096

typedef struct { uint8_t a, b; } synpair_t;

size_t nibble_pack(const uint8_t *in, size_t inlen, uint8_t *out) {
    for (size_t i = 0; i < inlen; ++i) if (in[i] > 0x0F) return 0;
    size_t outlen = (inlen + 1) / 2;
    for (size_t i = 0; i < inlen / 2; ++i) out[i] = (in[2*i] << 4) | in[2*i+1];
    if (inlen & 1) out[outlen-1] = (in[inlen-1] << 4);
    return outlen;
}

size_t nibble_unpack(const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, size_t origlen) {
    if (origlen > outmax) return 0;
    for (size_t i = 0; i < origlen / 2; ++i) {
        out[2*i] = in[i] >> 4;
        out[2*i+1] = in[i] & 0x0F;
    }
    if (origlen & 1) out[origlen-1] = in[inlen-1] >> 4;
    return origlen;
}

size_t bpe_compress(const uint8_t *in, size_t inlen, uint8_t *out, uint8_t *table, size_t *tablelen) {
    uint8_t buf1[2048], buf2[2048];
    memcpy(buf1, in, inlen);
    size_t buflen = inlen;
    uint8_t next_symbol = 255;
    size_t tlen = 0;
    for (int iter = 0; iter < 32 && next_symbol > 0; ++iter) {
        int counts[256][256] = {{0}};
        for (size_t i = 0; i + 1 < buflen; ++i) counts[buf1[i]][buf1[i+1]]++;
        int maxc = 1;
        uint8_t maxa = 0, maxb = 0;
        for (int a = 0; a < 256; ++a) for (int b = 0; b < 256; ++b) {
            if (counts[a][b] > maxc && a != next_symbol && b != next_symbol) {
                maxc = counts[a][b];
                maxa = (uint8_t)a;
                maxb = (uint8_t)b;
            }
        }
        if (maxc == 1) break;
        size_t j = 0;
        for (size_t i = 0; i < buflen;) {
            if (i + 1 < buflen && buf1[i] == maxa && buf1[i+1] == maxb) {
                buf2[j++] = next_symbol;
                i += 2;
            } else {
                buf2[j++] = buf1[i++];
            }
        }
        table[tlen++] = next_symbol;
        table[tlen++] = maxa;
        table[tlen++] = maxb;
        memcpy(buf1, buf2, j);
        buflen = j;
        next_symbol--;
    }
    memcpy(out, buf1, buflen);
    *tablelen = tlen;
    return buflen;
}

size_t bpe_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax, const uint8_t *table, size_t tablelen) {
    uint8_t buf1[2048], buf2[2048];
    memcpy(buf1, in, inlen);
    size_t buflen = inlen;
    for (int t = (int)tablelen - 3; t >= 0; t -= 3) {
        uint8_t sym = table[t], a = table[t+1], b = table[t+2];
        size_t j = 0;
        for (size_t i = 0; i < buflen; ++i) {
            if (buf1[i] == sym) {
                buf2[j++] = a;
                buf2[j++] = b;
            } else {
                buf2[j++] = buf1[i];
            }
        }
        memcpy(buf1, buf2, j);
        buflen = j;
        if (buflen > outmax) return 0;
    }
    memcpy(out, buf1, buflen);
    return buflen;
}

size_t rle_compress(const uint8_t *in, size_t inlen, uint8_t *out) {
    size_t outpos = 0;
    for (size_t i = 0; i < inlen;) {
        uint8_t val = in[i];
        size_t run = 1;
        while (i + run < inlen && in[i + run] == val && run < 255) run++;
        out[outpos++] = val;
        out[outpos++] = (uint8_t)run;
        i += run;
    }
    return outpos;
}

size_t rle_decompress(const uint8_t *in, size_t inlen, uint8_t *out, size_t outmax) {
    size_t inpos = 0, outpos = 0;
    while (inpos + 1 < inlen && outpos < outmax) {
        uint8_t val = in[inpos++];
        uint8_t run = in[inpos++];
        for (uint8_t j = 0; j < run && outpos < outmax; ++j) out[outpos++] = val;
    }
    return outpos;
}

void syn_generate_header_map(synpair_t map[256], uint8_t rev[64][64]) {
    int used[64][64] = {0};
    for (int i = 0; i < 256; ++i) {
        int a, b;
        do {
            a = rand() % 64;
            b = rand() % 64;
        } while (used[a][b]);
        used[a][b] = 1;
        map[i].a = (uint8_t)a;
        map[i].b = (uint8_t)b;
        rev[a][b] = (uint8_t)i;
    }
}

void syn_header_encode(const uint8_t *in, size_t len, char *out, const synpair_t map[256]) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(out + i * 7, "s%02dy%02dn", map[in[i]].a, map[in[i]].b);
    }
    out[len * 7] = 0;
}

size_t syn_header_decode(const char *in, uint8_t *out, size_t max, uint8_t rev[64][64]) {
    size_t inlen = strlen(in), count = 0;
    for (size_t i = 0; i + 6 < inlen && count < max; i += 7) {
        int a, b;
        if (sscanf(in + i, "s%2dy%2dn", &a, &b) != 2) break;
        out[count++] = rev[a][b];
    }
    return count;
}

void syn_generate_random_map(uint16_t map[256], uint8_t revmap[10000]) {
    for (int i = 0; i < 256; ++i) map[i] = i;
    for (int i = 255; i > 0; --i) {
        int j = rand() % (i + 1);
        uint16_t tmp = map[i];
        map[i] = map[j];
        map[j] = tmp;
    }
    for (int i = 0; i < 256; ++i) map[i] += 1000;
    for (int i = 0; i < 10000; ++i) revmap[i] = 0xFF;
    for (int i = 0; i < 256; ++i) revmap[map[i]] = (uint8_t)i;
}

void syn_encode_map(const uint8_t *in, size_t len, char *out, const uint16_t map[256]) {
    static const char *fmts[] = {
        "syn%04u", "sxxyxxn%04u", "sxyxxnx%04u", "xsxyxnx%04u", "sxyxnxx%04u"
    };
    size_t pos = 0;
    for (size_t i = 0; i < len; ++i) {
        int f = rand() % 5;
        pos += sprintf(out + pos, fmts[f], map[in[i]]);
    }
    out[pos] = 0;
}

size_t syn_decode_map(const char *in, uint8_t *out, const uint8_t revmap[10000]) {
    size_t inlen = strlen(in), count = 0, i = 0;
    while (i < inlen) {
        unsigned int val = 0;
        if (i + 7 <= inlen && strncmp(in + i, "syn", 3) == 0 && sscanf(in + i + 3, "%04u", &val) == 1) {
            i += 7;
        } else if (i + 11 <= inlen && strncmp(in + i, "sxxyxxn", 7) == 0 && sscanf(in + i + 7, "%04u", &val) == 1) {
            i += 11;
        } else if (i + 11 <= inlen && strncmp(in + i, "sxyxxnx", 7) == 0 && sscanf(in + i + 7, "%04u", &val) == 1) {
            i += 11;
        } else if (i + 11 <= inlen && strncmp(in + i, "xsxyxnx", 7) == 0 && sscanf(in + i + 7, "%04u", &val) == 1) {
            i += 11;
        } else if (i + 11 <= inlen && strncmp(in + i, "sxyxnxx", 7) == 0 && sscanf(in + i + 7, "%04u", &val) == 1) {
            i += 11;
        } else {
            break;
        }
        if (val >= 10000 || revmap[val] == 0xFF) break;
        out[count++] = revmap[val];
    }
    return count;
}

void mask_with_junk(const char *in, char *out, size_t inlen) {
    static const char junk[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    size_t j = 0, i = 0;
    while (i < inlen) {
        for (int r = 0; r < 2 && i < inlen; ++r) out[j++] = in[i++];
        out[j++] = junk[rand() % (sizeof(junk) - 1)];
    }
    out[j] = 0;
}

void unmask_junk(const char *in, char *out) {
    size_t j = 0, i = 0;
    while (in[i]) {
        for (int r = 0; r < 2 && in[i]; ++r) out[j++] = in[i++];
        if (in[i]) ++i;
    }
    out[j] = 0;
}

void derive_sbox_and_map_from_seed_and_nonce(const uint8_t seed[32], const uint8_t nonce[16], uint8_t sbox[256], uint16_t map[256], uint8_t revmap[10000]) {
    uint32_t state = 0;
    for (int i = 0; i < 32; ++i) state ^= ((uint32_t)seed[i]) << ((i % 4) * 8);
    for (int i = 0; i < 16; ++i) state ^= ((uint32_t)nonce[i]) << ((i % 4) * 8);
    for (int i = 0; i < 256; ++i) sbox[i] = (uint8_t)i;
    for (int i = 255; i > 0; --i) {
        state = state * 1664525 + 1013904223;
        int j = state % (i + 1);
        uint8_t tmp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    for (int i = 0; i < 256; ++i) map[i] = i;
    for (int i = 255; i > 0; --i) {
        state = state * 1664525 + 1013904223;
        int j = state % (i + 1);
        uint16_t tmp = map[i];
        map[i] = map[j];
        map[j] = tmp;
    }
    for (int i = 0; i < 10000; ++i) revmap[i] = 0xFF;
    for (int i = 0; i < 256; ++i) revmap[map[i]] = (uint8_t)i;
}

size_t hex_decode(const char *in, uint8_t *out) {
    size_t len = strlen(in) / 2;
    for (size_t i = 0; i < len; ++i) {
        unsigned int val = 0;
        sscanf(in + 2 * i, "%2x", &val);
        out[i] = (uint8_t)val;
    }
    return len;
}

int main(int argc, char **argv) {
    printf("\n========================================\n");
    printf("   SynCrypt - Polymorphic Crypter\n");
    printf("========================================\n");
    printf("Usage:\n");
    printf("  enc  - Encrypt text\n");
    printf("  dec  - Decrypt text\n");
    printf("  help - Show this help\n");
    printf("----------------------------------------\n");

    char mode[16];
    char key_hex[SYNCRYPT_KEY_SIZE * 2 + 2];
    char text[MAX_TEXT * 7 + 2];

    while (1) {
        printf("\nSelect mode (enc/dec/help): ");
        if (!fgets(mode, sizeof(mode), stdin)) return 1;
        mode[strcspn(mode, "\r\n")] = 0;
        if (strcmp(mode, "help") == 0) {
            printf("\nSynCrypt Usage:\n");
            printf("  enc  - Encrypt text with a key\n");
            printf("  dec  - Decrypt text with a key\n");
            printf("  help - Show this help message\n");
            continue;
        }
        if (strcmp(mode, "enc") != 0 && strcmp(mode, "dec") != 0) {
            printf("[!] Invalid mode. Please enter 'enc', 'dec', or 'help'.\n");
            continue;
        }
        break;
    }

    uint8_t key[SYNCRYPT_KEY_SIZE] = {0};
    size_t keylen = SYNCRYPT_KEY_SIZE;
    char genkey[8];
    while (1) {
        printf("Generate random key? (y/n): ");
        if (!fgets(genkey, sizeof(genkey), stdin)) return 1;
        genkey[strcspn(genkey, "\r\n")] = 0;
        if (genkey[0] == 'y' || genkey[0] == 'Y') {
            for (int i = 0; i < SYNCRYPT_KEY_SIZE; ++i) key[i] = (uint8_t)(rand() & 0xFF);
            printf("[Key] ");
            for (int i = 0; i < SYNCRYPT_KEY_SIZE; ++i) printf("%02x", key[i]);
            printf("  <-- Save this key!\n");
            break;
        } else if (genkey[0] == 'n' || genkey[0] == 'N') {
            printf("Enter key (hex, %d bytes): ", SYNCRYPT_KEY_SIZE);
            if (!fgets(key_hex, sizeof(key_hex), stdin)) return 1;
            key_hex[strcspn(key_hex, "\r\n")] = 0;
            keylen = hex_decode(key_hex, key);
            if (keylen != SYNCRYPT_KEY_SIZE) {
                printf("[!] Key must be %d bytes (hex encoded)!\n", SYNCRYPT_KEY_SIZE);
                continue;
            }
            break;
        } else {
            printf("[!] Please enter 'y' or 'n'.\n");
        }
    }

    printf("%s text: ", strcmp(mode, "enc") == 0 ? "Enter text to encrypt" : "Enter encrypted text (synXXXX)");
    if (!fgets(text, sizeof(text), stdin)) return 1;
    text[strcspn(text, "\r\n")] = 0;

    uint8_t inbuf[MAX_TEXT] = {0};
    uint8_t outbuf[MAX_TEXT + SYNCRYPT_BLOCK_SIZE] = {0};
    size_t inlen = 0;

    if (strcmp(mode, "enc") == 0) {
        inlen = strlen(text);
        memcpy(inbuf, text, inlen);

        uint8_t header_seed[32];
        uint8_t header_nonce[16];
        for (int i = 0; i < 32; ++i) header_seed[i] = (uint8_t)(rand() & 0xFF);
        for (int i = 0; i < 16; ++i) header_nonce[i] = (uint8_t)(rand() & 0xFF);

        uint8_t sbox[256];
        uint16_t map[256];
        uint8_t revmap[10000];
        derive_sbox_and_map_from_seed_and_nonce(header_seed, header_nonce, sbox, map, revmap);

        char header_syn_raw[(32+16)*2 + 1];
        for (int i = 0; i < 32; ++i) sprintf(header_syn_raw + i * 2, "%02x", header_seed[i]);
        for (int i = 0; i < 16; ++i) sprintf(header_syn_raw + 64 + i * 2, "%02x", header_nonce[i]);
        char header_syn[(32+16) * 3 + 1];
        mask_with_junk(header_syn_raw, header_syn, 96);

        syncrypt_encrypt_custom_sbox(inbuf, outbuf, inlen, key, keylen, sbox);
        size_t enclen = ((inlen + SYNCRYPT_BLOCK_SIZE - 1) / SYNCRYPT_BLOCK_SIZE) * SYNCRYPT_BLOCK_SIZE;
        char synout[MAX_TEXT * 7 + 1];
        syn_encode_map(outbuf, enclen, synout, map);
        char synout_masked[MAX_TEXT * 10 + 1];
        mask_with_junk(synout, synout_masked, strlen(synout));

        FILE *encf = fopen("enc.log", "w");
        if (encf) {
            fprintf(encf, "Header (paste for dec): %s\n", header_syn);
            fprintf(encf, "Encrypted : %s\n", synout_masked);
            fclose(encf);
            printf("[+] Output written to enc.log\n");
        } else {
            printf("[!] Failed to write to enc.log\n");
        }
    } else {
        char header_syn[(32+16) * 3 + 1];
        printf("Paste header from encryption output: ");
        if (!fgets(header_syn, sizeof(header_syn), stdin)) return 1;
        header_syn[strcspn(header_syn, "\r\n")] = 0;
        char header_syn_raw[(32+16) * 2 + 1];
        unmask_junk(header_syn, header_syn_raw);
        uint8_t header_seed[32];
        uint8_t header_nonce[16];
        for (int i = 0; i < 32; ++i) {
            unsigned int val = 0;
            sscanf(header_syn_raw + i * 2, "%2x", &val);
            header_seed[i] = (uint8_t)val;
        }
        for (int i = 0; i < 16; ++i) {
            unsigned int val = 0;
            sscanf(header_syn_raw + 64 + i * 2, "%2x", &val);
            header_nonce[i] = (uint8_t)val;
        }

        uint8_t sbox[256];
        uint16_t map[256];
        uint8_t revmap[10000];
        derive_sbox_and_map_from_seed_and_nonce(header_seed, header_nonce, sbox, map, revmap);

        char text_unmasked[MAX_TEXT * 7 + 1];
        unmask_junk(text, text_unmasked);
        inlen = syn_decode_map(text_unmasked, inbuf, revmap);
        syncrypt_decrypt_custom_sbox(inbuf, outbuf, inlen, key, keylen, sbox);
        outbuf[inlen] = 0;
        printf("Decrypted: %s\n", outbuf);
    }

    return 0;
}