#
# TencentBlueKing is pleased to support the open source community by making
# 蓝鲸智云 - 凭证管理服务(BlueKing - Key Management Service) available.
# Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
# Licensed under the MIT License (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
# http://opensource.org/licenses/MIT
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.We undertake not
# to change the open source license (MIT license) applicable to the current version
# of the project delivered to anyone in the future.
#

import base64
import hashlib
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from bk_kms import Client, CredentialType

SECRET_KEY = "test-secret-key"


class _KMSHandler(BaseHTTPRequestHandler):
    signature_valid = False
    request_payload: dict[str, Any] = {}

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        payload = json.loads(body)
        type(self).request_payload = payload
        content_hash = hashlib.sha256(body).hexdigest()
        string_to_sign = "\n".join(
            (
                self.headers["X-BKKMS-Timestamp"],
                self.headers["X-BKKMS-Nonce"],
                content_hash,
            )
        ).encode()
        signing_key = hmac.new(
            SECRET_KEY.encode(),
            self.headers["X-BKKMS-Nonce"].encode(),
            hashlib.sha256,
        ).digest()
        expected_signature = hmac.new(signing_key, string_to_sign, hashlib.sha256).hexdigest()
        type(self).signature_valid = hmac.compare_digest(
            expected_signature,
            self.headers["X-BKKMS-Signature"],
        )

        data_key = b"0123456789abcdef"
        public_key = serialization.load_pem_public_key(base64.b64decode(payload["public_key"]))
        encrypted_key = public_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        results = [
            {
                "credential_id": 1,
                "err_code": 0,
                "err_msg": "",
                "credential": {
                    "name": "database",
                    "type": "single_password",
                    "auth_info": {"password": "secret"},
                    "annotation": "test",
                },
            }
        ]
        plaintext = json.dumps(results, separators=(",", ":")).encode()
        padder = symmetric_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(data_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        envelope = {
            "asymmetric_type": "RSA",
            "symmetric_type": "AES",
            "symmetric_mode": "CBC",
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "ciphertext": base64.b64encode(iv + ciphertext).decode(),
        }
        envelope_text = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode()).decode()
        response = json.dumps(
            {
                "code": 0,
                "message": "OK",
                "data": {"envelope": envelope_text},
            },
            separators=(",", ":"),
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def test_client_round_trip_against_local_kms_stub() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _KMSHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    try:
        with Client(base_url=f"http://127.0.0.1:{server.server_port}", app_code="app", tenant_id="system") as client:
            results = client.consume_credential(
                access_key="test-access-key",
                secret_key=SECRET_KEY,
                credential_names=["database"],
            )

        assert _KMSHandler.signature_valid
        assert _KMSHandler.request_payload["credential_id_list"] == []
        assert _KMSHandler.request_payload["credential_name_list"] == ["database"]
        assert len(results) == 1
        assert results[0].ok
        assert results[0].credential is not None
        assert results[0].credential.type is CredentialType.SINGLE_PASSWORD
        assert results[0].credential.auth_info.password == "secret"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
