"""Dead Simple Signing Envelope
"""

import logging
from typing import Any, List

from securesystemslib import exceptions, formats
from securesystemslib.signer import GPGSignature, Signature
from securesystemslib.util import b64dec, b64enc

logger = logging.getLogger(__name__)


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: list of Signature and GPGSignature.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: List[Signature]
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Envelope":
        """Creates a Signature object from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".
            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = []
        for signature in data["signatures"]:
            if formats.GPG_SIGNATURE_SCHEMA.matches(signature):
                signatures.append(GPGSignature.from_dict(signature))
            elif formats.SIGNATURE_SCHEMA.matches(signature):
                signatures.append(Signature.from_dict(signature))
            else:
                raise exceptions.FormatError("Wanted a 'Signature'")

        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        return b"DSSEv1 %d %b %d %b" % (
            len(self.payload_type),
            self.payload_type.encode("utf-8"),
            len(self.payload),
            self.payload,
        )
