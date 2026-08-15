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

#pragma once

#include <string>

#include "Types.h"

// An RSA public key used only to verify signatures. The wawaka crypto extension
// exposes RSA for encryption but not for signature verification, so RSA proofs
// (e.g. an externally generated proof-of-possession credential) are verified
// here through OpenSSL instead. Signatures are RSASSA-PKCS1-v1_5 over a SHA-256
// digest of the message, which is the default OpenSSL RSA signature scheme.

namespace pdo_contracts
{
namespace crypto
{
    namespace signing
    {
        class RSAPublicKey
        {
        private:
            void* key_ = nullptr; // EVP_PKEY*, kept opaque so the header pulls in no OpenSSL

            void ResetKey(void);

        public:
            RSAPublicKey(void) {};
            RSAPublicKey(const std::string& encoded);
            ~RSAPublicKey();

            RSAPublicKey(const RSAPublicKey&) = delete;
            RSAPublicKey& operator=(const RSAPublicKey&) = delete;

            operator bool() const { return key_ != nullptr; };

            // Load a PEM-encoded SubjectPublicKeyInfo RSA public key.
            bool Deserialize(const std::string& encoded);

            // Verify an RSASSA-PKCS1-v1_5 signature over the SHA-256 digest of
            // message. signature holds the raw signature bytes.
            bool VerifySignature(
                const ww::types::ByteArray& message,
                const ww::types::ByteArray& signature) const;
        };
    }
}
}
