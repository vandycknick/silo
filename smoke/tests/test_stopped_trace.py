"""Wire-decoder unit tests, not injected lifecycle outcomes."""
import pytest

from silo_smoke.stopped_trace import protobuf_fields, thaw_reply


ACTIVATION = "f68e625c-60f4-4b88-91f0-c946ca645378"
MACHINE = "64f12618-dbbc-4dfe-a951-e22bd8c25088"
RUN = "d45a0733-cc5a-41ec-a794-8a44c3778a47"


def varint(value: int) -> bytes:
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number: int, value: bytes) -> bytes:
    return varint(number << 3 | 2) + varint(len(value)) + value


def response(state: int = 7, activation: str = ACTIVATION) -> bytes:
    reference = (field(1, MACHINE.encode()) + field(2, RUN.encode())
                 + field(3, ACTIVATION.encode()) + b"\x20\x01")
    status = (b"\x08" + varint(state) + field(2, reference)
              + field(8, MACHINE.encode()) + field(9, RUN.encode())
              + field(10, activation.encode()))
    message = field(1, status)
    return b"\0" + len(message).to_bytes(4, "big") + message


def frame(payload: bytes, kind: int = 0, stream: int = 1, flags: int = 0) -> bytes:
    return (len(payload).to_bytes(3, "big") + bytes((kind, flags))
            + stream.to_bytes(4, "big") + payload)


def test_thaw_reply_requires_complete_matching_thawed_status() -> None:
    message = response()
    wire = frame(b"", kind=4, stream=0) + frame(b"headers", kind=1) + frame(message)
    for end in range(len(wire)):
        assert thaw_reply(wire[:end], ACTIVATION) is None
    assert thaw_reply(wire, ACTIVATION) == {
        "state": "thawed", "activation": ACTIVATION, "machine": MACHINE,
        "run": RUN, "stream": 1, "grpcMessageHex": message.hex(),
    }
    assert thaw_reply(frame(response(state=6)), ACTIVATION) is None
    assert thaw_reply(frame(response(activation=MACHINE)), ACTIVATION) is None
    assert thaw_reply(frame(message, kind=1), ACTIVATION) is None
    assert thaw_reply(frame(b"\0\0\0\0\x02\x0a\0"), ACTIVATION) is None
    connected = b"OK 49152\n" + wire
    for end in range(len(connected)):
        assert thaw_reply(connected[:end], ACTIVATION) is None
    assert thaw_reply(connected, ACTIVATION)["state"] == "thawed"


def test_thaw_reply_reassembles_data_without_mixing_streams() -> None:
    message = response()
    for split in range(1, len(message)):
        first, last = message[:split], message[split:]
        unrelated = frame(b"not a lifecycle reply", stream=3)
        wire = frame(first) + unrelated + frame(last)
        assert thaw_reply(wire, ACTIVATION)["grpcMessageHex"] == message.hex()
        assert thaw_reply(frame(first) + frame(last, stream=3), ACTIVATION) is None
    padded = frame(b"\x02" + message + b"\0\0", flags=8)
    assert thaw_reply(padded, ACTIVATION)["state"] == "thawed"
    assert thaw_reply(frame(b"\xff", flags=8), ACTIVATION) is None


@pytest.mark.parametrize("data", [b"\x80", b"\0", b"\x0a\x05x", b"\x0b", b"\x80" * 10])
def test_protobuf_fields_rejects_malformed_wire(data: bytes) -> None:
    with pytest.raises(ValueError):
        protobuf_fields(data)
