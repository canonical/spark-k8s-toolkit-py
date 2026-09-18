import re

import pytest

from spark8t.utils import K8sSecretKeySerializer, PercentEncodingSerializer

requirement = re.compile(r"[-._a-zA-Z0-9]+")


def check_compliance(input_string: str) -> bool:
    if match := requirement.match(input_string):
        return match.group() == input_string
    return False


@pytest.mark.parametrize(
    "input_string",
    [
        "spark.*.property",
        "spark_property",
        "spark%property",
        "spark__property",
        "spark§property",
        "spark property",
        "spark%_property",
        "spark/property",
        "spark%property-foo/spark%property-bar",
    ],
)
def test_k8s_secret_key_serializer(input_string: str) -> None:
    """Test that the K8sSecretKeySerializer correctly serializes and deserializes input strings."""
    serializer = K8sSecretKeySerializer()
    serialized = serializer.serialize(input_string)
    assert check_compliance(serialized)
    assert serializer.deserialize(serialized) == input_string


@pytest.mark.parametrize(
    "input_string",
    [
        "spark.*.property",
        "spark_property",
        "spark%property",
        "spark__property",
        "spark§property",
        "spark property",
        "spark%_property",
    ],
)
def test_serializer_compatibility(input_string: str) -> None:
    """Test that the deprecated PercentEncodingSerializer and the current K8sSecretKeySerializer are compatible."""
    with pytest.warns(DeprecationWarning, match="use K8sSecretKeySerializer instead"):
        serializer_deprecated = PercentEncodingSerializer()
    serializer = K8sSecretKeySerializer()

    assert (
        serializer.deserialize(serializer_deprecated.serialize(input_string))
        == input_string
    )
    assert (
        serializer_deprecated.deserialize(serializer.serialize(input_string))
        == input_string
    )
