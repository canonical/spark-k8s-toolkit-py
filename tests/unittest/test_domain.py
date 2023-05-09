import logging
import unittest
import uuid

from spark_client.domain import Defaults, PropertyFile, ServiceAccount
from spark_client.services import InMemoryAccountRegistry
from spark_client.utils import umask_named_temporary_file
from tests import TestCase


class TestDomain(TestCase):
    def test_defaults(self):
        """
        Validates defaults passed in as environment.
        """
        home_var = str(uuid.uuid4())
        snap_var = str(uuid.uuid4())
        snap_user_data_dir = str(uuid.uuid4())
        snap_spark_env_conf_file = str(uuid.uuid4())
        snap_real_home = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())

        defaults = Defaults(
            environ={
                "HOME": home_var,
                "SNAP": snap_var,
                "SNAP_USER_DATA": snap_user_data_dir,
                "SPARK_CLIENT_ENV_CONF": snap_spark_env_conf_file,
                "SNAP_REAL_HOME": snap_real_home,
                "KUBECONFIG": kubeconfig,
            }
        )
        self.assertEqual(defaults.spark_folder, snap_var)
        self.assertEqual(
            defaults.static_conf_file, f"{snap_var}/conf/spark-defaults.conf"
        )
        self.assertEqual(
            defaults.dynamic_conf_file, f"{snap_user_data_dir}/spark-defaults.conf"
        )
        self.assertEqual(defaults.env_conf_file, f"{snap_spark_env_conf_file}")
        self.assertEqual(defaults.home_folder, f"{snap_real_home}")
        self.assertEqual(defaults.kube_config, f"{kubeconfig}")
        self.assertEqual(
            defaults.scala_history_file, f"{snap_user_data_dir}/.scala_history"
        )
        self.assertEqual(defaults.kubectl_cmd, f"{snap_var}/kubectl")
        self.assertEqual(defaults.spark_submit, f"{snap_var}/bin/spark-submit")
        self.assertEqual(defaults.spark_shell, f"{snap_var}/bin/spark-shell")
        self.assertEqual(defaults.pyspark, f"{snap_var}/bin/pyspark")

    def test_service_account(self):
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
        self.assertEqual(sa.id, f"{namespace}:{name}")
        self.assertEqual(
            sa.configurations.props.get(
                "spark.kubernetes.authenticate.driver.serviceAccountName"
            ),
            name,
        )
        self.assertEqual(
            sa.configurations.props.get("spark.kubernetes.namespace"), namespace
        )
        self.assertEqual(
            sa.configurations.props.get("spark.dummy.property1"), spark_dummy_property1
        )
        self.assertEqual(
            sa.configurations.props.get("spark.dummy.property2"), spark_dummy_property2
        )

    def test_property_file_parsing_from_confs(self):
        confs = ["key1=value1", "key2=value2"]

        prop = PropertyFile(
            dict(PropertyFile.parse_property_line(line) for line in confs)
        )

        self.assertEqual(len(prop.props), 2)
        self.assertEqual(prop.props, {"key1": "value1", "key2": "value2"})

    def test_property_file_parse_options(self):
        """
        Validates parsing of properties and options in PropertyFile abstraction.
        """
        name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        scala_hist_file = str(uuid.uuid4())

        props_with_option = (
            f'"-Dscala.shell.histfile={scala_hist_file} -Da=A -Db=B -Dc=C"'
        )

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

    def test_property_file_construct_options_string(self):
        """
        Validates construction of options string.
        """
        name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        scala_hist_file = str(uuid.uuid4())

        expected_props_with_option = (
            f" -Dscala.shell.histfile={scala_hist_file} -Da=A -Db=B -Dc=C"
        )

        conf = PropertyFile(
            props={
                "spark.kubernetes.authenticate.driver.serviceAccountName": name,
                "spark.kubernetes.namespace": namespace,
            }
        )

        self.assertEqual(
            conf._construct_options_string(
                options={
                    "scala.shell.histfile": f"{scala_hist_file}",
                    "a": "A",
                    "b": "B",
                    "c": "C",
                }
            ),
            expected_props_with_option,
        )

    def test_property_file_io(self):
        """
        Validates property file write and read.
        """
        name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        scala_hist_file = str(uuid.uuid4())
        app_name = str(uuid.uuid4())
        test_config_w = dict()
        contents_java_options = (
            f'-Dscala.shell.histfile = "{scala_hist_file} -Da=A -Db=B -Dc=C"'
        )

        test_config_w["spark.kubernetes.authenticate.driver.serviceAccountName"] = name
        test_config_w["spark.kubernetes.namespace"] = namespace
        test_config_w["spark.driver.extraJavaOptions"] = contents_java_options
        test_config_w["spark.app.name"] = app_name

        conf = PropertyFile(props=test_config_w)

        with umask_named_temporary_file(
            mode="w", prefix="spark-client-snap-unittest-", suffix=".test"
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

    def test_property_file_log(self):
        """
        Validates property file logging function.
        """
        k = str(uuid.uuid4())
        v = str(uuid.uuid4())

        # test logic
        conf = PropertyFile(props={k: v})
        with self.assertLogs("spark_client.domain.PropertyFile", level="INFO") as cm:
            conf.log()
        self.assertEqual(cm.output, [f"INFO:spark_client.domain.PropertyFile:{k}={v}"])

    def test_in_memory_registry(self):
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

        extraconf1 = PropertyFile(
            props={"spark.dummy.property1": spark_dummy_property1}
        )
        extraconf2 = PropertyFile(
            props={"spark.dummy.property2": spark_dummy_property2}
        )
        extraconf3 = PropertyFile(
            props={"spark.dummy.property3": spark_dummy_property3}
        )

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
        self.assertTrue(sa1 in all_sa)
        self.assertTrue(sa2 in all_sa)
        self.assertEqual(len(all_sa), 2)

        self.assertEqual(f"{namespace}:{name3}", registry.create(service_account=sa3))
        self.assertTrue(sa3 in registry.all())
        self.assertEqual(len(registry.all()), 3)

        deleted_account = registry.delete(f"{namespace}:{name1}")
        self.assertEqual(deleted_account, f"{namespace}:{name1}")
        self.assertTrue(sa1 not in registry.all())
        self.assertEqual(len(registry.all()), 2)

        self.assertEqual(registry.get_primary(), sa3)
        self.assertEqual(registry.set_primary(sa2.id), sa2.id)
        self.assertEqual(registry.get_primary(), sa2)

        self.assertEqual(registry.get(f"{namespace}:{name3}"), sa3)

        new_props = {
            "spark.dummy.property1": spark_dummy_property1,
            "spark.dummy.property2": spark_dummy_property2,
            "spark.dummy.property3": spark_dummy_property3,
        }
        self.assertEqual(
            sa2.id, registry.set_configurations(sa2.id, PropertyFile(props=new_props))
        )
        self.assertEqual(registry.get(sa2.id).extra_confs.props, new_props)


if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level="DEBUG")
    unittest.main()
