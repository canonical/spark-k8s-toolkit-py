import re

import pytest

from spark8t.utils import PercentEncodingSerializer, PropertyEncodingSerializer

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
    ],
)
def test_serializer_compatibility(input_string: str) -> None:
    """Test that the deprecated PercentEncodingSerializer and the current PropertyEncodingSerializer are compatible."""
    with pytest.warns(
        DeprecationWarning, match="use PropertyEncodingSerializer instead"
    ):
        serializer_deprecated = PercentEncodingSerializer()
    serializer = PropertyEncodingSerializer()

    serialized_deprecated = serializer_deprecated.serialize(input_string)
    assert check_compliance(serialized_deprecated)
    assert serializer_deprecated.deserialize(serialized_deprecated) == input_string

    serialized = serializer.serialize(input_string)
    assert check_compliance(serialized)
    assert serializer.deserialize(serialized) == input_string

    # Ensure that both serializers produce compliant output and are compatible to each other.
    assert serialized == serialized_deprecated
    assert serializer.deserialize(serialized_deprecated) == input_string
    assert serializer_deprecated.deserialize(serialized) == input_string


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
def test_property_encoding_serializer(input_string: str) -> None:
    """Test that the PropertyEncodingSerializer correctly serializes and deserializes input strings."""
    serializer = PropertyEncodingSerializer()
    serialized = serializer.serialize(input_string)
    assert check_compliance(serialized)
    assert serializer.deserialize(serialized) == input_string
