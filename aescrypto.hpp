#pragma once

#ifndef AES_CRYPTO_HPP
#define AES_CRYPTO_HPP

#include <string>
#include <vector>
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <base64.hpp>

std::string naviPwdEncKey = "just for obfuscation";

std::vector<uint8_t> keyTo32Bytes(const std::string& input) {
    std::vector<uint8_t> hash(32);
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(input.data()), input.size());
    mbedtls_sha256_finish(&ctx, hash.data());

    mbedtls_sha256_free(&ctx);

    return hash;
}

std::vector<uint8_t> generate_nonce(size_t nonce_size) {
    std::vector<uint8_t> nonce(nonce_size);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    mbedtls_ctr_drbg_random(&ctr_drbg, nonce.data(), nonce_size);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return nonce;
}

std::string encrypt(const std::vector<uint8_t>& encKey, const std::string& data) {
    std::vector<uint8_t> nonce = generate_nonce(12); // AES-GCM typically uses 12-byte nonce
    std::vector<uint8_t> output(data.size() + nonce.size() + 16); // Allocate space for nonce + ciphertext + tag

    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, encKey.data(), encKey.size() * 8);

    size_t tag_len = 16;
    size_t output_len = 0;
    size_t single_output_len;

    mbedtls_gcm_starts(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, nonce.data(), nonce.size());
    mbedtls_gcm_update(&gcm_ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size(), output.data() + nonce.size(), output.size() - nonce.size(), &single_output_len);
    output_len += single_output_len;
    mbedtls_gcm_finish(&gcm_ctx, output.data() + nonce.size() + output_len, output.size() - nonce.size() - output_len, &single_output_len, output.data() + output.size() - tag_len, tag_len);
    output_len += single_output_len;

    std::memcpy(output.data(), nonce.data(), nonce.size()); // Prepend nonce to output
    output.resize(nonce.size() + output_len + tag_len); // Resize to fit nonce + ciphertext + tag

    mbedtls_gcm_free(&gcm_ctx);
    return encodeToBase64(output);
}

std::string decrypt(const std::vector<uint8_t>& encKey, const std::string& data) {
    std::vector<uint8_t> encData = decodeFromBase64(data);
    std::vector<uint8_t> nonce(encData.begin(), encData.begin() + 12); // First 12 bytes are the nonce
    std::vector<uint8_t> ciphertext(encData.begin() + 12, encData.end());

    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, encKey.data(), encKey.size() * 8);

    std::vector<uint8_t> output(ciphertext.size() - 16); // Remove tag length (16 bytes)
    size_t output_len = 0;
    size_t single_output_len;

    mbedtls_gcm_starts(&gcm_ctx, MBEDTLS_GCM_DECRYPT, nonce.data(), nonce.size());
    mbedtls_gcm_update(&gcm_ctx, ciphertext.data(), ciphertext.size() - 16, output.data(), output.size(), &single_output_len);
    output_len += single_output_len;
    mbedtls_gcm_finish(&gcm_ctx, output.data() + output_len, output.size() - output_len, &single_output_len, ciphertext.data() + ciphertext.size() - 16, 16);
    output_len += single_output_len;

    mbedtls_gcm_free(&gcm_ctx);
    return std::string((char*)output.data(), output_len);
}

#endif // !AES_CRYPTO_HPP
