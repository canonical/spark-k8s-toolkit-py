import re

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from spark8t.utils import K8sSecretKeySerializer, PercentEncodingSerializer

requirement = re.compile(r"[-._a-zA-Z0-9]+")


def check_compliance(input_string: str) -> bool:
    if match := requirement.match(input_string):
        return match.group() == input_string
    return False


@given(
    input_string=st.one_of(
        st.text(min_size=1),
        st.text(alphabet="_%-/~.=?", min_size=1),
    )
)
@example("test-/-b")
@example("spark__property")
@example("_2f")
@example("spark%property")
@example("_")
@example("spark%property-foo/spark%property-bar")
def test_k8s_secret_key_serializer(input_string: str) -> None:
    """Test that the K8sSecretKeySerializer correctly serializes and deserializes input strings.

    There are two things that it should satisfy:
     - deserialize(serialize(x)) == x for any input
     - check_compliance(serialize(x)) == True for any input.
    """
    serializer = K8sSecretKeySerializer()
    serialized = serializer.serialize(input_string)
    assert check_compliance(serialized)
    assert serializer.deserialize(serialized) == input_string


@given(
    input_string=st.one_of(
        st.text(min_size=1),
        st.text(alphabet="_%-/~.=?", min_size=1),
    )
)
@example("spark__property")
@example("_2f")
@example("spark%property")
@example("_")
@example("spark%property-foo/spark%property-bar")
@example("test-/-b")
def test_serializer_compatibility(input_string: str) -> None:
    """Test that keys stored by the deprecated PercentEncodingSerializer can still be read."""
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
