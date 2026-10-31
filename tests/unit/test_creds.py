from __future__ import annotations

import base64

import pytest

from wapy.creds import (
    ADV_SECRET_LEN,
    REGISTRATION_ID_MAX,
    CredentialsError,
    DeviceCredentials,
    generate_credentials,
    signal_public_key,
)
from wapy.crypto.xeddsa import verify


def test_generate_produces_verifiable_material() -> None:
    credentials = generate_credentials()
    assert credentials.verify()
    assert verify(
        credentials.identity_public,
        b"\x05" + credentials.signed_pre_key.key_pair.public,
        credentials.signed_pre_key.signature,
    )


def test_generated_sizes_and_ranges() -> None:
    credentials = generate_credentials()
    assert len(credentials.noise_public) == 32
    assert len(credentials.identity_public) == 32
    assert len(credentials.signed_pre_key.signature) == 64
    assert 0 <= credentials.registration_id <= REGISTRATION_ID_MAX
    assert len(base64.b64decode(credentials.adv_secret_key)) == ADV_SECRET_LEN


def test_each_generation_is_distinct() -> None:
    first = generate_credentials()
    second = generate_credentials()
    assert first.noise_public != second.noise_public
    assert first.identity_public != second.identity_public
    assert first.adv_secret_key != second.adv_secret_key


def test_explicit_registration_id_is_kept() -> None:
    assert generate_credentials(registration_id=42).registration_id == 42


def test_registration_id_out_of_range_is_rejected() -> None:
    with pytest.raises(CredentialsError):
        generate_credentials(registration_id=REGISTRATION_ID_MAX + 1)


def test_signal_public_key_adds_prefix_once() -> None:
    assert signal_public_key(b"\x01" * 32) == b"\x05" + b"\x01" * 32
    assert signal_public_key(b"\x05" + b"\x02" * 32) == b"\x05" + b"\x02" * 32


def test_signal_public_key_rejects_wrong_length() -> None:
    with pytest.raises(CredentialsError):
        signal_public_key(b"\x01" * 31)


def test_dict_roundtrip_preserves_everything() -> None:
    credentials = generate_credentials()
    restored = DeviceCredentials.from_dict(credentials.to_dict())
    assert restored == credentials
    assert restored.verify()


def test_dict_is_json_safe() -> None:
    import json

    payload = json.dumps(generate_credentials().to_dict())
    assert DeviceCredentials.from_dict(json.loads(payload)).verify()


def test_missing_field_is_rejected() -> None:
    data = generate_credentials().to_dict()
    del data["noise_private"]
    with pytest.raises(CredentialsError):
        DeviceCredentials.from_dict(data)


def test_truncated_key_is_rejected() -> None:
    data = generate_credentials().to_dict()
    data["identity_public"] = base64.b64encode(b"short").decode()
    with pytest.raises(CredentialsError):
        DeviceCredentials.from_dict(data)


def test_non_base64_value_is_rejected() -> None:
    data = generate_credentials().to_dict()
    data["adv_secret_key"] = "not base64!!"
    with pytest.raises(CredentialsError):
        DeviceCredentials.from_dict(data)


def test_registration_id_range_is_enforced_on_load() -> None:
    data = generate_credentials().to_dict()
    data["registration_id"] = REGISTRATION_ID_MAX + 1
    with pytest.raises(CredentialsError):
        DeviceCredentials.from_dict(data)


def test_serialized_form_contains_no_private_key_as_plaintext_field_names() -> None:
    data = generate_credentials().to_dict()
    assert set(data) >= {"noise_public", "identity_public", "adv_secret_key"}
    assert all(isinstance(value, (str, int)) or value is None for value in data.values())
