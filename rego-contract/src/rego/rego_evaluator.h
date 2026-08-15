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

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"

// The rego_evaluator contract has a single responsibility: evaluate an arbitrary
// Rego policy over an arbitrary input at an arbitrary entrypoint and return the
// output. It is stateless. Its eval_rego helper (and the regorus custom
// allocator hooks) live in methods/rego_evaluator.cpp and are reused by
// rego_policy_agent.

// evaluate: { "rego_source": <rego>, "entrypoint": <data.x.y>, "input": <json> }
// rego_source / input are passed as strings (input is arbitrary JSON text).
#define REGO_EVALUATOR_EVALUATE_PARAM_SCHEMA  \
    "{"                                       \
        SCHEMA_KW(rego_source, "") ","        \
        SCHEMA_KW(entrypoint, "") ","         \
        SCHEMA_KW(input, "")                  \
    "}"

namespace ww
{
namespace rego
{
namespace rego_evaluator
{
    // Evaluate one Rego policy in its own fresh engine and return the JSON for
    // the requested rule. Reused by rego_policy_agent. On failure error_msg
    // explains why. (Defined in methods/rego_evaluator.cpp, alongside the
    // regorus allocator hooks.)
    bool eval_rego(
        const char* source,
        const char* entrypoint,
        const std::string& input_json,
        std::string& output_json,
        std::string& error_msg);

    // contract method: evaluate arbitrary rego_source over input at entrypoint
    bool evaluate(const Message& msg, const Environment& env, Response& rsp);

}; // rego_evaluator
}; // rego
}; // ww
