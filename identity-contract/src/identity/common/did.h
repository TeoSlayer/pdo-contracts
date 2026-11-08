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

// A PDO contract's decentralized identifier is derived from its contract id:
//   did:pdo:<contract_id>
// Defined once here (in the identity family) because it is common to any contract
// that refers to another PDO contract by its DID.
#define PDO_DID_PREFIX "did:pdo:"

namespace ww
{
namespace identity
{
    // The contract id behind an identifier. A PDO DID loses its prefix and any
    // #fragment (the signing context); anything else is returned unchanged, so a
    // bare contract id and the DIDs naming it all map to the same value.
    inline std::string contract_id_of(const std::string& id)
    {
        const std::string prefix(PDO_DID_PREFIX);
        if (id.compare(0, prefix.size(), prefix) != 0)
            return id;
        const std::string rest = id.substr(prefix.size());
        return rest.substr(0, rest.find('#'));
    }

    // The DID for an identifier: a bare contract id gains the PDO prefix, an
    // identifier that already is a DID is returned unchanged.
    inline std::string did_of(const std::string& id)
    {
        return id.compare(0, 4, "did:") == 0 ? id : std::string(PDO_DID_PREFIX) + id;
    }
}
}
