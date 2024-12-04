import pyspark
from lightkube import Client
from lightkube.core.exceptions import ApiError
from spark8t.services import K8sServiceAccountRegistry, LightKube
import socket

class SparkSession():

    def __init__(self, app_name: str, namespace: str, username: str):
        self.app_name = app_name
        self.namespace = namespace
        self.username = username
        self.session = None

    @property
    def _pod_ip(self, ):
        return socket.gethostbyname(socket.gethostname())
    

    @property
    def service_account(self, ):
        interface = LightKube(None, None)
        registry = K8sServiceAccountRegistry(interface)
        try:
            return registry.get(f"{self.namespace}:{self.username}")
        except (ApiError, AttributeError):
            return None        

    @property
    def _sa_props(self, ):
        if self.service_account is None:
            return {}
        return self.service_account.configurations.props 

    @property
    def _extra_props(self, ) -> dict:
        return {
            "spark.driver.host": self._pod_ip
        }

    @property
    def _k8s_master(self, ) -> str:
        return Client().config.cluster.server

    @property
    def config(self, ) -> dict:
        return self._sa_props | self._extra_props

    def __enter__(self, ):
        if self.session is not None:
            return self.session
    
        builder = pyspark.sql.SparkSession()\
                        .builder\
                        .appName(self.app_name)\
                        .master(f"k8s://{self._k8s_master}")

        for conf, val in self.config.items():
            builder = builder.config(conf, val)
        self.session = builder.getOrCreate()
        return self.session


    def __exit__(self, ):
        if self.session is not None:
            self.session.stop()
