import os
import random
from unittest import TestCase, skipIf

from spark8t.utils import create_dir_if_not_exists  # type: ignore

test_path = os.path.dirname(os.path.abspath(__file__))

DATA_FOLDER = os.path.join(test_path, "resources", "data")

integration_test_flag = bool(int(os.environ.get("IE_TEST", "0")))
integration_test = skipIf(
    integration_test_flag is False,
    "Integration test, to be skipped when running unittests",
)


class UnittestWithTmpFolder(TestCase):
    TMP_FOLDER = os.path.join("/tmp", "%032x" % random.getrandbits(128))

    @classmethod
    def setUpClass(cls) -> None:
        create_dir_if_not_exists(cls.TMP_FOLDER)

    @classmethod
    def tearDownClass(cls) -> None:
        os.system(f"rm -rf {cls.TMP_FOLDER}/*")
