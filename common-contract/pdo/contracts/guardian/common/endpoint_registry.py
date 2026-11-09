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

import shelve
import threading

from pdo.common.keys import EnclaveKeys

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EndpointRegistry(object) :

    # -------------------------------------------------------
    def __init__(self, filename = "endpoint.db") :
        logger.info('create endpoint registry in file %s', filename)
        self._lock = threading.RLock()
        self._registry = shelve.open(filename, flag='c', writeback=True)

    # -------------------------------------------------------
    def close(self) :
        with self._lock:
            self._registry.close()
            self._registry = None

    # -------------------------------------------------------
    def get_endpoint(self, contract_id) :
        with self._lock:
            (verifying_key, encryption_key) = self._registry[contract_id]
        return EnclaveKeys(verifying_key, encryption_key)

    # -------------------------------------------------------
    def set_endpoint(self, contract_id, verifying_key, encryption_key) :
        # Parse both public keys before changing persistent state.
        keys = EnclaveKeys(verifying_key, encryption_key)
        endpoint = (verifying_key, encryption_key)
        with self._lock:
            if contract_id in self._registry:
                if self._registry[contract_id] != endpoint:
                    raise ValueError('endpoint already registered with different keys')
            else:
                self._registry[contract_id] = endpoint
                self._registry.sync()
        return keys
