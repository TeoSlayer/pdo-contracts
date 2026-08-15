# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pdo.client.builder.shell import run_shell_command

import warnings

warnings.catch_warnings()
warnings.simplefilter("ignore")


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def rego_evaluator():
    run_shell_command("do_rego_evaluator", "pdo.rego.plugins.rego_evaluator")


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def rego_policy_agent():
    run_shell_command("do_rego_policy_agent", "pdo.rego.plugins.rego_policy_agent")


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def rego_token():
    run_shell_command("do_rego_token", "pdo.rego.plugins.rego_token")


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def rego_guardian():
    run_shell_command(
        "do_guardian_service", "pdo.contracts.guardian.plugins.guardian_service"
    )
