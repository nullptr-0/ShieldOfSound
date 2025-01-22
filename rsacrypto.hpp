#pragma once

#ifndef RSA_CRYPTO_HPP
#define RSA_CRYPTO_HPP

#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <string>
#include <vector>
#include <base64.hpp>

std::pair< std::string, std::string> generate_key_pair(size_t key_size = 2048) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        std::cerr << "Failed to setup PK context" << std::endl;
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return { "", "" };
    }

    mbedtls_rsa_context* rsa = mbedtls_pk_rsa(pk);
    if (mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size, 65537) != 0) {
        std::cerr << "Failed to generate RSA key" << std::endl;
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return { "", "" };
    }

    std::vector<uint8_t> private_key(key_size);
    mbedtls_pk_write_key_pem(&pk, private_key.data(), private_key.size());

    std::vector<uint8_t> public_key(key_size);
    mbedtls_pk_write_pubkey_pem(&pk, public_key.data(), public_key.size());

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return { std::string((char*)private_key.data(), private_key.size()), std::string((char*)public_key.data(), public_key.size()) };
}

std::string RsaEncrypt(const std::string& data, const std::string& public_key_pem) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    if (mbedtls_pk_parse_public_key(&pk,
        reinterpret_cast<const uint8_t*>(public_key_pem.c_str()),
        public_key_pem.size() + 1) != 0) {
        throw std::runtime_error("Failed to parse public key.");
    }

    std::vector<uint8_t> encrypted_data(256); // Adjust size as needed
    size_t encrypted_length;

    if (mbedtls_pk_encrypt(&pk,
        reinterpret_cast<const uint8_t*>(data.data()),
        data.size(),
        encrypted_data.data(),
        &encrypted_length,
        encrypted_data.size(),
        mbedtls_ctr_drbg_random,
        &ctr_drbg) != 0) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error("Encryption failed.");
    }
    
    if (encrypted_data.size() != encrypted_length) {
        encrypted_data.resize(encrypted_length);
    }

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return encodeVecToBase64(encrypted_data);
}

std::string RsaDecrypt(const std::string& data, const std::string& private_key_pem) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    if (mbedtls_pk_parse_key(&pk,
        reinterpret_cast<const uint8_t*>(private_key_pem.c_str()),
        private_key_pem.size() + 1,
        nullptr,
        0,
        mbedtls_ctr_drbg_random,
        &ctr_drbg) != 0) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error("Failed to parse private key.");
    }

    std::vector<uint8_t> encrypted_data = decodeVecFromBase64(data);

    std::vector<uint8_t> decrypted_data(256); // Adjust size as needed
    size_t decrypted_length;

    if (mbedtls_pk_decrypt(&pk,
        reinterpret_cast<const uint8_t*>(encrypted_data.data()),
        encrypted_data.size(),
        decrypted_data.data(),
        &decrypted_length,
        decrypted_data.size(),
        mbedtls_ctr_drbg_random,
        &ctr_drbg) != 0) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        throw std::runtime_error("Decryption failed.");
    }

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return std::string(reinterpret_cast<char*>(decrypted_data.data()), decrypted_length);
}

#endif // !RSA_CRYPTO_HPP
