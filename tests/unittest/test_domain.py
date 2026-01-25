import logging
import os
import tempfile
import uuid

import pytest

from spark8t.domain import Defaults, ServiceAccount
from spark8t.registry.memory import InMemoryAccountRegistry
from spark8t.utils import PropertyFile, umask_named_temporary_file


def test_defaults():
    """
    Validates defaults passed in as environment.
    """
    spark_home = str(uuid.uuid4())
    user_data_dir = str(uuid.uuid4())
    spark_env_conf_file = str(uuid.uuid4())
    kubeconfig = str(uuid.uuid4())
    kubectl_cmd = str(uuid.uuid4())

    defaults = Defaults(
        environ={
            "SPARK_HOME": spark_home,
            "SPARK_USER_DATA": user_data_dir,
            "SPARK_CLIENT_ENV_CONF": spark_env_conf_file,
            "KUBECONFIG": kubeconfig,
            "SPARK_KUBECTL": kubectl_cmd,
        }
    )
    assert defaults.spark_home, spark_home
    assert defaults.static_conf_file == f"{spark_home}/conf/spark-defaults.conf"
    assert defaults.env_conf_file, f"{spark_env_conf_file}"

    assert defaults.kube_config, f"{kubeconfig}"
    assert defaults.scala_history_file, f"{user_data_dir}/.scala_history"
    assert defaults.kubectl_cmd, kubectl_cmd
    assert defaults.spark_submit, f"{spark_home}/bin/spark-submit"
    assert defaults.spark_shell, f"{spark_home}/bin/spark-shell"
    assert defaults.pyspark, f"{spark_home}/bin/pyspark"


def test_defaults_kube_config():
    """
    Validates defaults passed in as environment.
    """

    from spark8t.utils import environ

    d = Defaults({})

    assert d.kube_config is None

    with environ(KUBECONFIG="my-kube-config"):
        d = Defaults(dict(os.environ))
        assert d.kube_config == "my-kube-config"


def test_service_account():
    """
    Validates service account including defending namespace and account name against overrides.
    """
    name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    name_incorrect = str(uuid.uuid4())
    namespace_incorrect = str(uuid.uuid4())
    apiserver = f"k8s://https://{str(uuid.uuid4())}:{str(uuid.uuid4())}"
    spark_dummy_property1 = str(uuid.uuid4())
    spark_dummy_property2 = str(uuid.uuid4())

    extraconf = PropertyFile(
        props={
            "spark.kubernetes.authenticate.driver.serviceAccountName": name_incorrect,
            "spark.kubernetes.namespace": namespace_incorrect,
            "spark.dummy.property1": spark_dummy_property1,
            "spark.dummy.property2": spark_dummy_property2,
        }
    )

    sa = ServiceAccount(
        name=name, namespace=namespace, api_server=apiserver, extra_confs=extraconf
    )
    assert sa.id == f"{namespace}:{name}"
    assert (
        sa.configurations.props.get(
            "spark.kubernetes.authenticate.driver.serviceAccountName"
        )
        == name
    )
    assert sa.configurations.props.get("spark.kubernetes.namespace") == namespace
    assert sa.configurations.props.get("spark.dummy.property1") == spark_dummy_property1
    assert sa.configurations.props.get("spark.dummy.property2") == spark_dummy_property2


def test_property_removing_conf():
    """
    Validates removal of configuration options.
    """
    confs = ["key1=value1", "key2=value2", "key3=value3"]

    prop = PropertyFile(dict(PropertyFile.parse_property_line(line) for line in confs))

    assert "key1" not in prop.remove(["key1"]).props

    assert "key3" in prop.remove(["key1", "key2"]).props

    assert prop.props == prop.remove([]).props


def test_property_removing_conf_with_pairs():
    """
    Validates the correct removal of property pairs.
    """
    confs = ["key1=value1", "key2=value2", "key3=value3"]

    prop = PropertyFile(dict(PropertyFile.parse_property_line(line) for line in confs))

    assert "key1" not in prop.remove(["key1=value1"]).props

    assert "key1" in prop.remove(["key1=value2"]).props

    assert "key1" not in prop.remove(["key1=value2", "key1=value1"]).props

    assert "key1" not in prop.remove(["key1", "key1=value2"]).props


def test_property_empty_lines():
    """
    Validates that empty lines are skipped and configuration is parsed correctly.
    """
    confs = [
        "key1=value1",
        "",
        "key2=value2",
        "key3=value3",
        "",
        "#key4=value4",
        " #key5=value5",
    ]

    with tempfile.NamedTemporaryFile(mode="w+t") as f:
        # write conf file
        for conf in confs:
            f.write(f"{conf}\n")
        f.flush()

        with open(f.name, "r") as fp:
            assert len(fp.readlines()) == 7

        # read property file from temporary file name
        prop = PropertyFile.read(f.name)

        assert "key1" not in prop.remove(["key1=value1"]).props

        assert "key1" in prop.remove(["key1=value2"]).props

        assert "key1" not in prop.remove(["key1=value2", "key1=value1"]).props

        assert "key1" not in prop.remove(["key1", "key1=value2"]).props

        assert "key4" not in prop.props

        assert "#key4" not in prop.props

        assert "key5" not in prop.props

        assert "#key5" not in prop.props


def test_property_file_parsing_from_confs():
    """
    Validates parsing of configuration from list.
    """
    confs = ["key1=value1", "key2=value2"]

    prop = PropertyFile(dict(PropertyFile.parse_property_line(line) for line in confs))

    assert len(prop.props) == 2
    assert prop.props == {"key1": "value1", "key2": "value2"}


def test_property_file_parse_options():
    """
    Validates parsing of properties and options in PropertyFile abstraction.
    """
    name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    scala_hist_file = str(uuid.uuid4())

    props_with_option = f"-Dscala.shell.histfile={scala_hist_file} -Da=A -Db=B -Dc=C"

    conf = PropertyFile(
        props={
            "spark.kubernetes.authenticate.driver.serviceAccountName": name,
            "spark.kubernetes.namespace": namespace,
        }
    )

    options = conf._parse_options(props_with_option)

    assert options["scala.shell.histfile"] == f"{scala_hist_file}"
    assert options["a"] == "A"
    assert options["b"] == "B"
    assert options["c"] == "C"


def test_property_file_construct_options_string():
    """
    Validates construction of options string.
    """
    scala_hist_file = str(uuid.uuid4())

    expected_props_with_option = (
        f"-Dscala.shell.histfile={scala_hist_file} -Da=A -Db=B -Dc=C"
    )

    assert (
        PropertyFile._construct_options_string(
            options={
                "scala.shell.histfile": f"{scala_hist_file}",
                "a": "A",
                "b": "B",
                "c": "C",
            }
        )
        == expected_props_with_option
    )


def test_property_file_io():
    """
    Validates property file write and read.
    """
    name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    scala_hist_file = str(uuid.uuid4())
    app_name = str(uuid.uuid4())
    test_config_w = {}
    contents_java_options = (
        f"-Dscala.shell.histfile={scala_hist_file} -Da=A -Db=B -Dc=C"
    )

    test_config_w["spark.kubernetes.authenticate.driver.serviceAccountName"] = name
    test_config_w["spark.kubernetes.namespace"] = namespace
    test_config_w["spark.driver.extraJavaOptions"] = contents_java_options
    test_config_w["spark.app.name"] = app_name

    conf = PropertyFile(props=test_config_w)

    with umask_named_temporary_file(
        mode="w", prefix="spark8t-unittest-", suffix=".test"
    ) as t:
        conf.write(t.file)
        t.flush()
        test_config_r = conf.read(t.name)
        assert (
            test_config_r.props.get(
                "spark.kubernetes.authenticate.driver.serviceAccountName"
            )
            == name
        )
        assert test_config_r.props.get("spark.kubernetes.namespace") == namespace
        assert (
            test_config_r.props.get("spark.driver.extraJavaOptions")
            == contents_java_options
        )
        assert test_config_r.props.get("spark.app.name") == app_name


@pytest.mark.parametrize(
    "key",
    [
        "spark.driver.defaultJavaOptions",
        "spark.driver.extraJavaOptions",
        "spark.executor.defaultJavaOptions",
        "spark.executor.extraJavaOptions",
    ],
)
def test_merge_property_file_options(tmp_path, key):
    """
    Validates property file write and read.
    """
    filename_1 = os.path.join(tmp_path, "test-1.properties")
    with open(filename_1, "w") as fid:
        fid.write(f"{key}=-Da=A -Db=B")

    filename_2 = os.path.join(tmp_path, "test-2.properties")
    with open(filename_2, "w") as fid:
        fid.write(f"{key}=-Da=D -Dc=C")

    conf_1 = PropertyFile.read(filename_1)
    conf_2 = PropertyFile.read(filename_2)

    assert len(conf_1.options[key]) == 2

    assert conf_1.options[key]["a"] == "A"

    assert conf_1.props[key] == "-Da=A -Db=B"

    merged = conf_1 + conf_2

    assert len(merged.options[key]) == 3

    assert merged.options[key]["a"] == "D"

    assert merged.props[key] == "-Da=D -Db=B -Dc=C"


def test_property_file_log(caplog):
    """
    Validates property file logging function.
    """
    k = str(uuid.uuid4())
    v = str(uuid.uuid4())

    # test logic
    conf = PropertyFile(props={k: v})
    caplog.set_level("INFO", logger="spark8t.utils.PropertyFile")
    with caplog.at_level("INFO"):
        conf.log()
        assert len(caplog.records) == 1
        assert caplog.records[0].message == f"{k}={v}"
        assert caplog.records[0].levelno == logging.INFO
        assert caplog.records[0].name == "spark8t.utils.PropertyFile"


def test_in_memory_registry():
    """
    Validate in memory registry functionalities.
    """
    name1 = str(uuid.uuid4())
    name2 = str(uuid.uuid4())
    name3 = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    apiserver = f"k8s://https://{str(uuid.uuid4())}:{str(uuid.uuid4())}"
    spark_dummy_property1 = str(uuid.uuid4())
    spark_dummy_property2 = str(uuid.uuid4())
    spark_dummy_property3 = str(uuid.uuid4())

    extraconf1 = PropertyFile(props={"spark.dummy.property1": spark_dummy_property1})
    extraconf2 = PropertyFile(props={"spark.dummy.property2": spark_dummy_property2})
    extraconf3 = PropertyFile(props={"spark.dummy.property3": spark_dummy_property3})

    sa1 = ServiceAccount(
        name=name1,
        namespace=namespace,
        api_server=apiserver,
        extra_confs=extraconf1,
    )
    sa2 = ServiceAccount(
        name=name2,
        namespace=namespace,
        api_server=apiserver,
        extra_confs=extraconf2,
    )
    sa2.primary = True

    sa3 = ServiceAccount(
        name=name3,
        namespace=namespace,
        api_server=apiserver,
        extra_confs=extraconf3,
    )
    sa3.primary = True

    registry = InMemoryAccountRegistry(
        {f"{namespace}:{sa1.name}": sa1, f"{namespace}:{sa2.name}": sa2}
    )
    all_sa = registry.all()
    assert sa1 in all_sa
    assert sa2 in all_sa
    assert len(all_sa) == 2

    assert f"{namespace}:{name3}" == registry.create(service_account=sa3)
    assert sa3 in registry.all()
    assert len(registry.all()) == 3

    deleted_account = registry.delete(f"{namespace}:{name1}")
    assert deleted_account, f"{namespace}:{name1}"
    assert sa1 not in registry.all()
    assert len(registry.all()) == 2

    assert registry.get_primary() == sa3
    assert registry.set_primary(sa2.id) == sa2.id
    assert registry.get_primary() == sa2

    assert registry.get(f"{namespace}:{name3}") == sa3

    new_props = {
        "spark.dummy.property1": spark_dummy_property1,
        "spark.dummy.property2": spark_dummy_property2,
        "spark.dummy.property3": spark_dummy_property3,
    }
    assert sa2.id, registry.set_configurations(sa2).id == PropertyFile(props=new_props)
    assert registry.get(sa2.id).extra_confs.props, new_props


def test_extra_prop_overrides_hub():
    # Given
    apiserver = f"k8s://https://{str(uuid.uuid4())}:{str(uuid.uuid4())}"
    sa = ServiceAccount(
        name="name",
        namespace="namespace",
        api_server=apiserver,
        extra_confs=PropertyFile(props={"spark.dummy.property": "extra_value"}),
        integration_hub_confs=PropertyFile(props={"spark.dummy.property": "hub_value"}),
    )

    # When
    configuration = sa.configurations

    # Then
    assert configuration.props.get("spark.dummy.property", "") == "extra_value"
