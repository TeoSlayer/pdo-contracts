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


"""
This file defines the InvokeApp class, a WSGI interface class for
handling contract method invocation requests.
"""

from pdo.contracts.guardian.common.utility import ValidateJSON
from pdo.rego.utils import AsymmetricEncryption
import logging
import base64

logger = logging.getLogger(__name__)


# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class DownloadOperation:
    # the capability parameters are the policy_decision credential's claims,
    # forwarded verbatim by the rego_token; the only field this operation needs is
    # the channel key it encrypts the data for
    # -----------------------------------------------------------------
    __schema__ = {
        "type": "object",
        "properties": {
            "channel_key": {"type": "string"},
        },
        "required": ["channel_key"],
    }

    # -----------------------------------------------------------------
    def __init__(self, config):
        # Model Parameters to be used during inference
        self.data = "secret_data"

    def __encrypted_data(self, channel_key):
        # Encrypt the data using the provided channel key

        return AsymmetricEncryption().encrypt(channel_key.encode(), self.data.encode())

    # -----------------------------------------------------------------
    def __call__(self, params):
        if not ValidateJSON(params, self.__schema__):
            return None
        channel_key = params["channel_key"]
        enc_data = self.__encrypted_data(channel_key)

        return base64.b64encode(enc_data).decode()
