"""Serialization module provides abstract base classes and concrete
implementations to serialize and deserialize objects.
"""

import abc
import json
from typing import Any

from securesystemslib.exceptions import (
    DeserializationError,
    SerializationError,
)


class BaseDeserializer(metaclass=abc.ABCMeta):
    """Abstract base class for deserialization of objects."""

    @abc.abstractmethod
    def deserialize(self, raw_data: bytes, cls: Any) -> Any:
        """Deserialize bytes to a specific object."""
        raise NotImplementedError


class JSONDeserializer(BaseDeserializer):
    """Provides raw to JSON deserialize method."""

    def deserialize(self, raw_data: bytes, cls: Any) -> Any:
        """Deserialize utf-8 encoded JSON bytes into an instance of cls.

        Arguments:
            raw_data: A utf-8 encoded bytes string.
            cls: A class type having a from_dict method.

        Returns:
            Object of the provided class type.
        """

        try:
            json_dict = json.loads(raw_data.decode("utf-8"))
            obj = cls.from_dict(json_dict)

        except Exception as e:
            raise DeserializationError("Failed to deserialize bytes") from e

        return obj


class BaseSerializer(metaclass=abc.ABCMeta):
    """Abstract base class for serialization of objects."""

    @abc.abstractmethod
    def serialize(self, obj: Any) -> bytes:
        """Serialize an object to bytes."""
        raise NotImplementedError


class JSONSerializer(BaseSerializer):
    """Provide an object to bytes serialize method.

    Attributes:
        compact: A boolean indicating if the JSON bytes generated in
            'serialize' should be compact by excluding whitespace.
    """

    def __init__(self, compact: bool = False):
        self.indent = 1
        self.separators = (",", ": ")
        if compact:
            self.indent = None
            self.separators = (",", ":")

    def serialize(self, obj: Any) -> bytes:
        """Serialize an object into utf-8 encoded JSON bytes.

        Arguments:
            obj: An object with to_dict method.

        Returns:
            UTF-8 encoded JSON bytes of the object.
        """

        try:
            json_bytes = json.dumps(
                obj.to_dict(),
                indent=self.indent,
                separators=self.separators,
                sort_keys=True,
            ).encode("utf-8")

        except Exception as e:
            raise SerializationError("Failed to serialize JSON") from e

        return json_bytes
