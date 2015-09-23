import os

# Environment variables for API reference.
KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT', 'http://localhost:8080/api/v1/')
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
if ETCD_AUTHORITY_ENV not in os.environ:
    os.environ[ETCD_AUTHORITY_ENV] = 'kubernetes-master:6666'

# Append to existing env, to avoid losing PATH etc.
# Need to edit the path here since calicoctl loads client on import.
CALICOCTL_PATH = os.environ.get('CALICOCTL_PATH', '/usr/bin/calicoctl')

# Flag to indicate whether or not to use Calico IPAM.
# If False, use the default docker container ip address to create container.
# If True, use libcalico's auto_assign IPAM to create container.
CALICO_IPAM = os.environ.get('CALICO_IPAM', 'true')

# Flag to indicate whether or not to use Calico Policy.
# Determines the default policy profile.
CALICO_POLICY = os.environ.get('CALICO_POLICY', 'false')

# Namespacesd keys for Calico configured annotations
ANNOTATION_NAMESPACE = "projectcalico.org/"
EPID_ANNOTATION_KEY = "%sendpointID" % ANNOTATION_NAMESPACE

# Log information for Kubernetes Plugin
KUBERNETES_LOG_DIR = "/var/log/calico/kubernetes"
POLICY_LOG = "%s/policy-agent.log" % KUBERNETES_LOG_DIR
PLUGIN_LOG = "%s/calico.log" % KUBERNETES_LOG_DIR

LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

# Profile names for default profiles.
DEFAULT_PROFILE_REJECT = "REJECT_ALL"
DEFAULT_PROFILE_ACCEPT = "ALLOW_ALL"

# Valid Policy strings.
POLICY_OPEN = "Open"
POLICY_CLOSED = "Closed"
SVC_TYPE_NAMESPACE_IP = "NamespaceIP"