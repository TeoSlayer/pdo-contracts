/* Copyright 2026 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "exchange/common/Common.h"

#include "identity/crypto/CryptoInternal.h"
#include "identity/crypto/RSAPublicKey.h"

#include "Types.h"

namespace signing = pdo_contracts::crypto::signing;
namespace crypto = pdo_contracts::crypto;

// -----------------------------------------------------------------
// Constructor from PEM-encoded public key
// -----------------------------------------------------------------
signing::RSAPublicKey::RSAPublicKey(const std::string& encoded)
{
    if (! Deserialize(encoded))
        CONTRACT_SAFE_ABORT("Crypto Error (RSAPublicKey::RSAPublicKey): Could not deserialize public key");
}

// -----------------------------------------------------------------
// Destructor
// -----------------------------------------------------------------
signing::RSAPublicKey::~RSAPublicKey()
{
    ResetKey();
}

// -----------------------------------------------------------------
void signing::RSAPublicKey::ResetKey(void)
{
    if (key_ != nullptr)
    {
        EVP_PKEY_free(reinterpret_cast<EVP_PKEY*>(key_));
        key_ = nullptr;
    }
}

// -----------------------------------------------------------------
// Deserialize a PEM-encoded SubjectPublicKeyInfo RSA public key
// -----------------------------------------------------------------
bool signing::RSAPublicKey::Deserialize(const std::string& encoded)
{
    ResetKey();

    crypto::BIO_ptr bio(BIO_new_mem_buf(encoded.c_str(), -1), BIO_free_all);
    ERROR_IF_NULL(bio, "Crypto Error (RSAPublicKey::Deserialize): Could not create BIO");

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), NULL, NULL, NULL);
    ERROR_IF_NULL(pkey, "Crypto Error (RSAPublicKey::Deserialize): Could not deserialize RSA public key");

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
    {
        EVP_PKEY_free(pkey);
        ERROR_IF(true, "Crypto Error (RSAPublicKey::Deserialize): key is not an RSA key");
    }

    key_ = pkey;
    return true;
}

// -----------------------------------------------------------------
// Verify an RSASSA-PKCS1-v1_5 / SHA-256 signature over message
// -----------------------------------------------------------------
bool signing::RSAPublicKey::VerifySignature(
    const ww::types::ByteArray& message,
    const ww::types::ByteArray& signature) const
{
    ERROR_IF_NULL(key_, "Crypto Error (RSAPublicKey::VerifySignature): public key not initialized");

    crypto::EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ERROR_IF_NULL(md_ctx, "Crypto Error (RSAPublicKey::VerifySignature): Could not create digest context");

    int res = EVP_DigestVerifyInit(
        md_ctx.get(), NULL, EVP_sha256(), NULL, reinterpret_cast<EVP_PKEY*>(key_));
    ERROR_IF(res <= 0, "Crypto Error (RSAPublicKey::VerifySignature): Could not initialize verification");

    // EVP_DigestVerify returns 1 for a valid signature, 0 for an invalid one and
    // a negative value on error; only a valid signature counts as verified
    res = EVP_DigestVerify(
        md_ctx.get(), signature.data(), signature.size(), message.data(), message.size());
    ERROR_IF(res < 0, "Crypto Error (RSAPublicKey::VerifySignature): error while verifying signature");
    ERROR_IF(res == 0, "Crypto Error (RSAPublicKey::VerifySignature): invalid signature");

    return true;
}
