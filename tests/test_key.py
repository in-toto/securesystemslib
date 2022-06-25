#!/usr/bin/env python

"""Test cases for "key.py". """

import copy
import unittest

import securesystemslib.formats
import securesystemslib.keys as KEYS
from securesystemslib.exceptions import (
    CryptoError,
    FormatError,
)
from securesystemslib.key import SSlibKey
from securesystemslib.signer import SSlibSigner


class TestSSlibKey(unittest.TestCase):
    """SSlibKey Test Case."""

    @classmethod
    def setUpClass(cls):
        cls.key_pairs = [
            KEYS.generate_rsa_key(),
            KEYS.generate_ed25519_key(),
            KEYS.generate_ecdsa_key(),
        ]
        cls.DATA_STR = "SOME DATA REQUIRING AUTHENTICITY."
        cls.DATA = securesystemslib.formats.encode_canonical(cls.DATA_STR).encode(
            "utf-8"
        )

    def test_sslib_verify(self):
        """Test to check verify method of key."""

        for key_pair in self.key_pairs:
            sslib_signer = SSlibSigner(key_pair)
            sig_obj = sslib_signer.sign(self.DATA)

            # Verify signature.
            sslib_key = SSlibKey.from_securesystemslib_key(key_pair)
            verified = sslib_key.verify(sig_obj, self.DATA)
            self.assertTrue(verified, "Incorrect signature.")

            # Test for invalid public key.
            public = key_pair["keyval"]["public"]
            key_pair["keyval"]["public"] = ""
            sslib_key = SSlibKey.from_securesystemslib_key(key_pair)

            with self.assertRaises((CryptoError, FormatError)):
                sslib_key.verify(sig_obj, self.DATA)

            key_pair["keyval"]["public"] = public

    def test_sslib_serialization(self):
        """Test to check serialization methods of key."""

        for key_pair in self.key_pairs:
            # Format key.
            key_dict = KEYS.format_keyval_to_metadata(
                key_pair["keytype"],
                key_pair["scheme"],
                key_pair["keyval"],
            )
            # key_dict contains keyid_hash_algorithms.
            key_dict.pop("keyid_hash_algorithms")

            keyid = key_pair["keyid"]

            # Test for load and dump key_dict.
            sslib_key = SSlibKey.from_dict(copy.copy(key_dict), keyid)
            self.assertEqual(key_dict, sslib_key.to_dict())

            # Test for load and dump securesystemslib_key.
            key_dict["keyid"] = keyid
            sslib_key = SSlibKey.from_securesystemslib_key(key_dict)
            self.assertEqual(key_dict, sslib_key.to_securesystemslib_key())

            # Test for invalid keytype.
            valid_keytype = key_pair["keytype"]
            key_pair["keytype"] = "invalid_keytype"
            with self.assertRaises(FormatError):
                SSlibKey.from_securesystemslib_key(key_pair)

            key_pair["keytype"] = valid_keytype

    def test_sslib_equality(self):
        """Test to check equality of key."""

        for key_pair in self.key_pairs:
            # Create two keys.
            sslib_key = SSlibKey.from_securesystemslib_key(key_pair)
            sslib_key_2 = SSlibKey.from_securesystemslib_key(key_pair)

            # Assert not equal with key_pair.
            self.assertNotEqual(key_pair, sslib_key)

            # Assert equality of two keys created from same securesystemslib_key.
            self.assertEqual(sslib_key_2, sslib_key)

            # Assert equality of key created from dict of first sslib_key.
            sslib_key_2 = SSlibKey.from_securesystemslib_key(
                sslib_key.to_securesystemslib_key()
            )
            self.assertEqual(sslib_key_2, sslib_key)

            # Assert inequalities.
            sslib_key_2.scheme = "invalid"
            self.assertNotEqual(sslib_key_2, sslib_key)
            sslib_key_2.scheme = sslib_key.scheme

            sslib_key_2.keytype = "invalid"
            self.assertNotEqual(sslib_key_2, sslib_key)
            sslib_key_2.keytype = sslib_key.keytype

            sslib_key_2.keyval = {"public": "invalid"}
            self.assertNotEqual(sslib_key_2, sslib_key)
            sslib_key_2.keyval = sslib_key.keyval

            self.assertEqual(sslib_key_2, sslib_key)


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
