#ifndef SYNCRYPT_H
#define SYNCRYPT_H

#include <stdint.h>
#include <stddef.h>

#define SYNCRYPT_KEY_SIZE 16
#define SYNCRYPT_BLOCK_SIZE 16
#define SYNCRYPT_HEADER_SIZE 24

#ifdef __cplusplus
extern "C" {
#define RESTRICT
#else
#define RESTRICT restrict
#endif

void syncrypt_encrypt(const uint8_t *RESTRICT in, uint8_t *RESTRICT out, size_t len, const uint8_t *RESTRICT key, size_t keylen);
void syncrypt_decrypt(const uint8_t *RESTRICT in, uint8_t *RESTRICT out, size_t len, const uint8_t *RESTRICT key, size_t keylen);
void syncrypt_encrypt_custom_sbox(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, size_t keylen, const uint8_t *sbox);
void syncrypt_decrypt_custom_sbox(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, size_t keylen, const uint8_t *sbox);

#ifdef __cplusplus
}
#endif

#endif