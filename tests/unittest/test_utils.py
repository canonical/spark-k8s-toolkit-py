import re

import pytest

from spark8t.utils import PercentEncodingSerializer

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
def test_serializer(input_string: str) -> None:
    serializer = PercentEncodingSerializer()
    serialized = serializer.serialize(input_string)
    assert check_compliance(serialized)
    assert serializer.deserialize(serialized) == input_string
