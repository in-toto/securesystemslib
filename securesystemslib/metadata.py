"""Dead Simple Signing Envelope
"""

import abc
import json
from typing import Any, List

from securesystemslib import exceptions, formats
from securesystemslib.signer import Signature
from securesystemslib.util import b64dec, b64enc


class Envelope:
    """
    DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body
        payload_type: string that identifies how to interpret payload
        signatures: List of Signature and GPG Signature

    Methods:
        from_dict(cls, data):
            Creates a Signature object from its JSON/dict representation.

        to_dict(self):
            Returns the JSON-serializable dictionary representation of self.

    """

    payload: bytes
    payload_type: str
    signatures: List[Signature]

    def __init__(self, payload, payload_type, signatures):
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
                raise NotImplementedError

            if formats.SIGNATURE_SCHEMA.matches(signature):
                signatures.append(Signature.from_dict(signature))

            else:
                raise exceptions.FormatError("Wanted a 'Signature'.")

        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

    @property
    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        return b"DSSEv1 %d %b %d %b" % (
            len(self.payload_type),
            self.payload_type.encode("utf-8"),
            len(self.payload),
            self.payload,
        )


class Parser:
    """A Generic Payload Parser.

    Attributes:
        _supported_payload_types: A list of supported payload types in lowercase.

    Methods:
        check_type(cls, payload_type: str):
            Checks the parser support given payload type.

        parse(envelope: Envelope):
            Parse the envelope's payload.
    """

    __metaclass__ = abc.ABCMeta
    _supported_payload_types: List[str] = []

    @classmethod
    def check_type(cls, payload_type: str) -> None:
        """Checks the parser support given payload type.

        Arguments:
            payload_type: The payload_type to be checked.

        Raises:
            UnsupportedPayloadType: if payload_type is not a supported payload type.
        """

        if payload_type not in cls._supported_payload_types:
            raise exceptions.UnsupportedPayloadType

    @classmethod
    @abc.abstractmethod
    def parse(cls, envelope: Envelope) -> Any:
        """Parse the envelope's payload.

        Arguments:
            envelope: The DSSE "Envelope" class instance.

        Returns:
            Returns the serialized body.
        """
        raise NotImplementedError  # pragma: no cover


class SSlibParser(Parser):
    """An example parser for securesystemslib.

    This parser is created to test the capabilities of the Generic Parser class
    and provide reference to implement a parser according to the application
    and type of payload.
    """

    _supported_payload_types: List[str] = ["application/vnd.sslib+json"]

    @classmethod
    def parse(cls, envelope: Envelope) -> dict:
        """Parse the envelope's payload into dict.

        Arguments:
            envelope: The DSSE "Envelope" class instance.

        Returns:
            Returns the parsed body.
        """

        cls.check_type(envelope.payload_type)
        try:
            return json.loads(envelope.payload)
        except json.JSONDecodeError as exc:
            raise exceptions.PayloadParseError(
                "error during payload parsing, please check the payload"
            ) from exc
