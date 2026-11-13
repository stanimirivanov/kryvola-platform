"""Bounded inspection of the real Temporal history in the admitted workflow role."""

import asyncio
import base64
import importlib
import json
import sys


def measure(history):
    if not 1 <= len(history.events) <= 128 or history.ByteSize() > 1 << 20:
        raise ValueError("M1_HISTORY_BOUND")
    maximum = 0

    def document(value):
        if isinstance(value, dict):
            if set(map(str.lower, value)) & {
                "token",
                "authorization",
                "credentials",
                "private_key",
                "client_key",
                "ciphertext",
                "proof",
                "approval_base64url",
                "manifest_base64url",
            }:
                raise ValueError("M1_HISTORY_PRIVATE_FIELD")
            for child in value.values():
                document(child)
        elif isinstance(value, list):
            for child in value:
                document(child)

    def walk(message):
        nonlocal maximum
        name = message.DESCRIPTOR.full_name
        if name == "temporal.api.common.v1.Payloads" and message.ByteSize() > 128 << 10:
            raise ValueError("M1_HISTORY_CALL_BOUND")
        if name == "temporal.api.common.v1.Payload":
            size = message.ByteSize()
            if size > 32768:
                raise ValueError("M1_HISTORY_PAYLOAD_BOUND")
            maximum = max(maximum, size)
            encoding = message.metadata.get("encoding")
            if encoding == b"binary/null" and not message.data:
                return
            if encoding != b"json/plain":
                raise ValueError("M1_HISTORY_ENCODING")
            document(json.loads(message.data))
            return
        for field, value in message.ListFields():
            if field.message_type is None:
                continue
            if field.is_repeated:
                children = value.values() if field.message_type.GetOptions().map_entry else value
                for child in children:
                    if hasattr(child, "ListFields"):
                        walk(child)
            else:
                walk(value)

    walk(history)
    if maximum == 0:
        raise ValueError("M1_HISTORY_NO_PAYLOADS")
    return {"events": len(history.events), "payload_max_bytes": maximum}


async def main(identifier):
    client_type = importlib.import_module("temporalio.client").Client
    converter = importlib.import_module("kryvola_fabric.compute_workflow").DATA_CONVERTER
    client = await client_type.connect("temporal:7233", data_converter=converter)
    handle = client.get_workflow_handle(identifier)
    # Completion is checked independently from the SQL disclosure record.
    result = await handle.result()
    if result.get("outcome") != "RELEASED":
        raise ValueError("M1_HISTORY_NOT_RELEASED")
    fetched = await handle.fetch_history()
    history = importlib.import_module("temporalio.api.history.v1").History(events=fetched.events)
    observed = measure(history)
    print(
        json.dumps(
            {
                "observed": observed,
                "result": result,
                "history_base64": base64.b64encode(history.SerializeToString()).decode(),
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(sys.argv[1]), 20))
