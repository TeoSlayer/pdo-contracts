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

#include <stdlib.h>
#include <stdint.h>
#include <string>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "rego/rego_evaluator.h"

extern "C"
{
#include "regorus/regorus.h"
}

// Custom allocator hooks called by regorus (custom_allocator feature). The
// wawaka runtime's malloc returns wasm-default-aligned pointers and aligned
// new is explicitly unsupported (see common/Util.cpp). Over-allocate and
// stash the raw base pointer in the slot preceding the aligned address so
// regorus_free can recover it.
//
// These live here (compiled into the ww_identity library) so that any contract
// that calls eval_rego -- rego_evaluator and rego_policy_agent -- gets them;
// contracts that never touch regorus drop them via function-level GC.
extern "C" uint8_t *regorus_aligned_alloc(size_t alignment, size_t size)
{
    if (alignment < sizeof(void *))
        alignment = sizeof(void *);
    const size_t total = size + alignment + sizeof(void *);
    void *raw = malloc(total);
    if (raw == nullptr)
        return nullptr;
    uintptr_t aligned = ((uintptr_t)raw + sizeof(void *) + alignment - 1) & ~(uintptr_t)(alignment - 1);
    ((void **)aligned)[-1] = raw;
    return (uint8_t *)aligned;
}

extern "C" void regorus_free(uint8_t *ptr)
{
    if (ptr == nullptr)
        return;
    free(((void **)ptr)[-1]);
}

// -----------------------------------------------------------------
// Evaluate one Rego policy in its own fresh engine and return the JSON for the
// requested rule. A fresh engine per policy keeps peak memory to one engine
// plus one compiled module, which suits the memory-limited runtime. On failure
// error_msg explains why.
// -----------------------------------------------------------------
bool ww::rego::rego_evaluator::eval_rego(
    const char *source,
    const char *entrypoint,
    const std::string &input_json,
    std::string &output_json,
    std::string &error_msg)
{
    RegorusEngine *engine = regorus_engine_new();
    if (engine == nullptr)
    {
        error_msg.assign("unexpected error, failed to create regorus engine");
        return false;
    }

    bool ok = true;

    RegorusResult r = regorus_engine_add_policy(engine, "policy.rego", source);
    if (r.status != Ok)
    {
        error_msg.assign(r.error_message ? r.error_message : "add_policy failed");
        ok = false;
    }
    regorus_result_drop(r);

    if (ok)
    {
        r = regorus_engine_set_input_json(engine, input_json.c_str());
        if (r.status != Ok)
        {
            error_msg.assign(r.error_message ? r.error_message : "set_input_json failed");
            ok = false;
        }
        regorus_result_drop(r);
    }

    if (ok)
    {
        r = regorus_engine_eval_rule(engine, entrypoint);
        if (r.status != Ok)
        {
            error_msg.assign(r.error_message ? r.error_message : "eval_rule failed");
            ok = false;
        }
        else if (r.output != nullptr)
        {
            output_json.assign(r.output);
        }
        regorus_result_drop(r);
    }

    regorus_engine_drop(engine);
    return ok;
}

// -----------------------------------------------------------------
// METHOD: evaluate
//   Evaluate an arbitrary Rego policy over an arbitrary input at an arbitrary
//   entrypoint and return the output. The contract is stateless.
//
// JSON PARAMETERS:
//   REGO_EVALUATOR_EVALUATE_PARAM_SCHEMA
//     { "rego_source": <rego>, "entrypoint": <data.x.y>, "input": <json text> }
//
// RETURNS:
//   the entrypoint's output, as a JSON string (whatever the rule produced)
// -----------------------------------------------------------------
bool ww::rego::rego_evaluator::evaluate(
    const Message &msg, const Environment &env, Response &rsp)
{
    ASSERT_SUCCESS(rsp, msg.validate_schema(REGO_EVALUATOR_EVALUATE_PARAM_SCHEMA),
                   "invalid request, missing 'rego_source', 'entrypoint', or 'input'");

    const char *rego_source = msg.get_string("rego_source");
    const char *entrypoint = msg.get_string("entrypoint");
    const char *input = msg.get_string("input");
    ASSERT_SUCCESS(rsp, rego_source != nullptr && entrypoint != nullptr && input != nullptr,
                   "invalid request, ill-formed parameters");

    std::string output_json;
    std::string error_msg;
    ASSERT_SUCCESS(rsp, ww::rego::rego_evaluator::eval_rego(
                            rego_source, entrypoint, std::string(input), output_json, error_msg),
                   error_msg.c_str());

    ww::value::String output(output_json.c_str());
    return rsp.value(output, false);
}
