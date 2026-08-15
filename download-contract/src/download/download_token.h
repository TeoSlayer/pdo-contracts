/* Copyright 2023 Intel Corporation
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

#include "Util.h"
#include "identity/common/Credential.h"

#define DOWNLOAD_PARAM_SCHEMA                   \
    "{"                                         \
        SCHEMA_KWS(download_vc, VERIFIABLE_CREDENTIAL_SCHEMA)              \
    "}"

#define DOWNLOAD_CAPABILITY_SCHEMA              \
    "{"                                         \
        SCHEMA_KW(channel_key,"") ","              \
        SCHEMA_KW(op,"")              \
    "}"

namespace ww
{
    namespace download
    {
        namespace download_token
        {
            // methods
            // bool initialize_contract(const Environment& env);
            bool do_download(const Message &msg, const Environment &env, Response &rsp);
        }; // download_token
    }; // download
}; // ww
