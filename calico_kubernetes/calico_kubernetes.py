#!/bin/python
import json
import sys
import socket
from subprocess import check_output, CalledProcessError, check_call
import logging

from docker import Client
from docker.errors import APIError
import sh
from netaddr import IPAddress, AddrFormatError

import common
from common.util import _patch_api, configure_logger
from common.constants import *
import pycalico
from pycalico import netns
from pycalico.datastore import RULES_PATH
from pycalico.datastore_datatypes import Rule, Rules
from pycalico.util import get_host_ips
from pycalico.ipam import IPAMClient
from pycalico.block import AlreadyAssignedError

logger = logging.getLogger(__name__)
util_logger = logging.getLogger(common.util.__name__)
pycalico_logger = logging.getLogger(pycalico.__name__)

# Docker and Host information.
DOCKER_VERSION = "1.16"
ORCHESTRATOR_ID = "docker"
HOSTNAME = socket.gethostname()


class NetworkPlugin(object):

    def __init__(self):
        self.pod_name = None
        self.profile_name = None
        self.namespace = None
        self.docker_id = None

        self._datastore_client = IPAMClient()
        self.calicoctl = sh.Command(CALICOCTL_PATH).bake(_env=os.environ)
        self._docker_client = Client(
            version=DOCKER_VERSION,
            base_url=os.getenv("DOCKER_HOST", "unix://var/run/docker.sock"))

    def create(self, namespace, pod_name, docker_id):
        """"Create a pod."""
        # Calicoctl does not support the '-' character in iptables rule names.
        # TODO: fix Felix to support '-' characters.
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace
        self.profile_name = DEFAULT_PROFILE_REJECT if CALICO_POLICY == 'true' \
            else DEFAULT_PROFILE_ACCEPT

        logger.info('Configuring docker container %s', self.docker_id)

        try:
            endpoint = self._configure_interface()
            self._configure_profile(endpoint)
        except CalledProcessError as e:
            logger.error('Error code %d creating pod networking: %s\n%s',
                         e.returncode, e.output, e)
            sys.exit(1)

        # Give the policy agent a reference to the endpoint in the API.
        # Only done after Endpoint configuration to avoid Policy Agent Race Condition.
        resource_path = "namespaces/%(namespace)s/pods/%(podname)s" % \
                        {"namespace": self.namespace, "podname": self.pod_name}
        ep_data = '{"metadata":{"annotations":{"%s":"%s"}}}' % (
            EPID_ANNOTATION_KEY, endpoint.endpoint_id)
        _patch_api(path=resource_path, patch=ep_data)

    def delete(self, namespace, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id
        self.namespace = namespace

        logger.info('Deleting container %s', self.docker_id)

        # Remove the profile for the workload.
        self._container_remove()

    def status(self, namespace, pod_name, docker_id):
        self.namespace = namespace
        self.pod_name = pod_name
        self.docker_id = docker_id

        # Find the endpoint
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.error("Container %s doesn't contain any endpoints", self.docker_id)
            sys.exit(1)

        # Retrieve IPAddress from the attached IPNetworks on the endpoint
        # Since Kubernetes only supports ipv4, we'll only check for ipv4 nets
        if not endpoint.ipv4_nets:
            logger.error("Exiting. No IPs attached to endpoint %s", self.docker_id)
            sys.exit(1)
        else:
            ip_nets = list(endpoint.ipv4_nets)
            if len(ip_nets) is not 1:
                logger.warning("There is more than one IPNetwork attached to"
                               "endpoint %s", self.docker_id)
            ip = ip_nets[0].ip

        logger.info("Retrieved IP Address: %s", ip)

        json_dict = {
            "apiVersion": "v1beta1",
            "kind": "PodNetworkStatus",
            "ip": str(ip)
        }

        logger.debug("Writing json dict to stdout: \n%s", json.dumps(json_dict))
        print json.dumps(json_dict)

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile for a pod.

        Currently assumes one pod with each name.
        """
        logger.info('Configuring Pod Profile: %s', self.profile_name)

        if self._datastore_client.profile_exists(self.profile_name):
            logger.debug("Profile %s already exists, no work to do", self.profile_name)
        else:
            logger.info("Creating Profile %s", self.profile_name)
            self._datastore_client.create_profile(self.profile_name)
            self._apply_rules()

        # Also set the profile for the workload.
        logger.info('Setting profile %s on endpoint %s',
                    self.profile_name, endpoint.endpoint_id)

        self._datastore_client.set_profiles_on_endpoint(profile_names=[self.profile_name],
                                                        endpoint_id=endpoint.endpoint_id)
        logger.info('Finished configuring profile.')

    def _configure_interface(self):
        """
        Configure the Calico interface for a pod.

        This involves the following steps:
        1) Obtain container PID and create a Calico endpoint using PID
        2) Delete the docker-assigned veth pair that's attached to the docker
           bridge
        3) Create a new calico veth pair, using the docker-assigned IP for the
           end in the container's namespace
        4) Assign the node's IP to the host end of the veth pair (required for
           compatibility with kube-proxy REDIRECT iptables rules).
        """
        logger.info('Configuring Calico network interface')

        # Set up parameters
        container_pid = self._get_container_pid(self.docker_id)
        interface = 'eth0'
        endpoint = self._container_add(container_pid, interface)
        namespace = netns.PidNamespace(container_pid)

        # Delete the existing veth connecting to the docker bridge.
        self._delete_docker_interface()

        # Create the veth, move into the container namespace, add the IP and
        # set up the default routes.
        logger.info("Creating the veth with namespace pid %s on interface name %s", container_pid, interface)
        endpoint.mac = endpoint.provision_veth(namespace, interface)

        # Update the endpoint to set the new mac address
        logger.info("Setting mac address %s to endpoint %s", endpoint.mac, endpoint.name)
        self._datastore_client.set_endpoint(endpoint)

        # This is slightly tricky. Since the kube-proxy sometimes
        # programs REDIRECT iptables rules, we MUST have an IP on the host end
        # of the caliXXX veth pairs. This is because the REDIRECT rule
        # rewrites the destination ip/port of traffic from a pod to a service
        # VIP. The destination port is rewriten to an arbitrary high-numbered
        # port, and the destination IP is rewritten to one of the IPs allocated
        # to the interface. This fails if the interface doesn't have an IP,
        # so we allocate an IP which is already allocated to the node. We set
        # the subnet to /32 so that the routing table is not affected;
        # no traffic for the node_ip's subnet will use the /32 route.
        node_ip = self._get_node_ip()
        logger.info('Adding IP %s to interface %s', node_ip, endpoint.name)
        check_call(['ip', 'addr', 'add', node_ip + '/32',
                    'dev', endpoint.name])

        logger.info('Finished configuring Calico network interface')
        return endpoint

    def _container_add(self, pid, interface):
        """
        Adds a new endpoint to the Calico datastore
        """
        # Check if the container already exists. If it does, exit.
        try:
            _ = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            # Calico doesn't know about this container.  Continue.
            pass
        else:
            logger.error("This container has already been configured with "
                         "Calico Networking.")
            sys.exit(1)

        # Obtain information from Docker Client and validate container state
        self._validate_container_state(self.docker_id)

        # Assign and retrieve container IP address
        ip_list = [self._assign_container_ip()]

        # Create Endpoint object
        try:
            logger.info("Creating endpoint with IPs %s", ip_list)
            ep = self._datastore_client.create_endpoint(HOSTNAME, ORCHESTRATOR_ID,
                                                        self.docker_id, ip_list)
        except (AddrFormatError, KeyError):
            logger.exception("Failed to create endpoint with IPs %s. Unassigning "
                             "IP address, then exiting.", ip_list)
            self._datastore_client.release_ips(set(ip_list))
            sys.exit(1)

        if CALICO_NETWORKING == 'true':
            # Create the veth, move into the container namespace, add the IP and
            # set up the default routes.
            logger.info(
                "Creating the veth with namespace pid %s on interface name %s", pid, interface)
            ep.mac = ep.provision_veth(netns.PidNamespace(pid), interface)

        logger.info("Setting mac address %s to endpoint %s", ep.mac, ep.name)
        self._datastore_client.set_endpoint(ep)

        # Give Kubernetes a link to the endpoint
        resource_path = "namespaces/%(namespace)s/pods/%(podname)s" % \
                        {"namespace": self.namespace, "podname": self.pod_name}
        ep_data = '{"metadata":{"annotations":{"%s":"%s"}}}' % (
            EPID_ANNOTATION_KEY, ep.endpoint_id)
        self._patch_api(path=resource_path, patch=ep_data)

        # Let the caller know what endpoint was created.
        return ep

    def _assign_container_ip(self):
        """
        Assign IPAddress either with the assigned docker IPAddress or utilize
        calico IPAM.

        The option to utilize IPAM is indicated by the environment variable
        "CALICO_IPAM".
        True indicates to utilize Calico's auto_assign IPAM policy.
        False indicate to utilize the docker assigned IPAddress

        :return IPAddress which has been assigned
        """
        if CALICO_IPAM == 'true':
            # Assign IP address through IPAM Client
            logger.info("Using Calico IPAM")
            try:
                ip_list, ipv6_addrs = self._datastore_client.auto_assign_ips(
                    1, 0, self.docker_id, None)
                ip = ip_list[0]
                logger.debug("ip_list is %s; ipv6_addrs is %s", ip_list, ipv6_addrs)
                assert not ipv6_addrs
            except RuntimeError as err:
                logger.error("Cannot auto assign IPAddress: %s", err.message)
                sys.exit(1)
        else:
            logger.info("Using docker assigned IP address")
            ip = self._read_docker_ip()
            try:
                self._datastore_client.assign_ip(ip, str(self.docker_id), None)
            except (ValueError, RuntimeError, AlreadyAssignedError):
                logger.exception("Cannot assign IPAddress %s", ip)
                sys.exit(1)

        return ip

    def _container_remove(self):
        """
        Remove the indicated container on this host from Calico networking
        """
        # Find the endpoint ID. We need this to find any ACL rules
        try:
            endpoint = self._datastore_client.get_endpoint(
                hostname=HOSTNAME,
                orchestrator_id=ORCHESTRATOR_ID,
                workload_id=self.docker_id
            )
        except KeyError:
            logger.exception("Container %s doesn't contain any endpoints",
                             self.docker_id)
            sys.exit(1)

        # Remove any IP address assignments that this endpoint has
        ip_set = set()
        for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
            ip_set.add(net.ip)
        logger.info("Removing IP addresses %s from endpoint %s", ip_set, endpoint.name)
        self._datastore_client.release_ips(ip_set)

        # Remove the veth interface from endpoint
        if CALICO_NETWORKING == 'true':
            logger.info(
                "Removing veth interface from endpoint %s", endpoint.name)
            try:
                netns.remove_veth(endpoint.name)
            except CalledProcessError:
                logger.exception("Could not remove veth interface from endpoint %s",
                                 endpoint.name)

        # Remove the container/endpoint from the datastore.
        try:
            self._datastore_client.remove_workload(
                HOSTNAME, ORCHESTRATOR_ID, self.docker_id)
            logger.info("Successfully removed workload from datastore")
        except KeyError:
            logger.exception("Failed to remove workload.")

        logger.info("Removed Calico interface from %s", self.docker_id)

    def _validate_container_state(self, container_name):
        info = self._get_container_info(container_name)

        # Check the container is actually running.
        if not info["State"]["Running"]:
            logger.error("The container is not currently running.")
            sys.exit(1)

        # We can't set up Calico if the container shares the host namespace.
        if info["HostConfig"]["NetworkMode"] == "host":
            logger.error("Can't add the container to Calico because it is "
                         "running NetworkMode = host.")
            sys.exit(1)

    def _get_container_info(self, container_name):
        try:
            info = self._docker_client.inspect_container(container_name)
        except APIError as e:
            if e.response.status_code == 404:
                logger.error("Container %s was not found. Exiting.", container_name)
            else:
                logger.error(e.message)
            sys.exit(1)
        return info

    def _get_container_pid(self, container_name):
        return self._get_container_info(container_name)["State"]["Pid"]

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        info = self._get_container_info(self.docker_id)
        ip = info["NetworkSettings"]["IPAddress"]
        logger.info('Docker-assigned IP is %s', ip)
        return IPAddress(ip)

    def _get_node_ip(self):
        """
        Determine the IP for the host node.
        """
        # Compile list of addresses on network, return the first entry.
        # Try IPv4 and IPv6.
        addrs = get_host_ips(version=4) or get_host_ips(version=6)

        try:
            addr = addrs[0]
            logger.info('Using IP Address %s', addr)
            return addr
        except IndexError:
            # If both get_host_ips return empty lists, print message and exit.
            logger.exception('No Valid IP Address Found for Host - cannot '
                             'configure networking for pod %s. Exiting' % (self.pod_name))
            sys.exit(1)

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        logger.info('Deleting docker interface eth0')

        # Get the PID of the container.
        pid = str(self._get_container_pid(self.docker_id))
        logger.info('Container %s running with PID %s', self.docker_id, pid)

        # Set up a link to the container's netns.
        logger.info("Linking to container's netns")
        logger.debug(check_output(['mkdir', '-p', '/var/run/netns']))
        netns_file = '/var/run/netns/' + pid
        if not os.path.isfile(netns_file):
            logger.debug(check_output(['ln', '-s', '/proc/' + pid + '/ns/net',
                                       netns_file]))

        # Reach into the netns and delete the docker-allocated interface.
        logger.debug(check_output(['ip', 'netns', 'exec', pid,
                                   'ip', 'link', 'del', 'eth0']))

        # Clean up after ourselves (don't want to leak netns files)
        logger.debug(check_output(['rm', netns_file]))

    def _get_pod_ports(self, pod):
        """
        Get the list of ports on containers in the Pod.

        :return list ports: the Kubernetes ContainerPort objects for the pod.
        """
        ports = []
        for container in pod['spec']['containers']:
            try:
                more_ports = container['ports']
                logger.info('Adding ports %s', more_ports)
                ports.extend(more_ports)
            except KeyError:
                pass
        return ports

    def _apply_rules(self):
        """
        Generate a default rules for a pod based on the profile name

        The name of the profile is set using the value of the environment
        variable CALICO_POLICY.

        If CALICO_POLICY is true, then the rules will be
        deny all inbound traffic and allow all outbound traffic
        If CALICO_POLICY is false, then the rules will be
        allow all inbound and outbound traffic

        :return:
        """
        try:
            profile = self._datastore_client.get_profile(self.profile_name)
        except:
            logger.error("Could not apply rules. Profile not found: %s, exiting",
                         self.profile_name)
            sys.exit(1)

        # Determine rule set based on policy
        if self.profile_name == DEFAULT_PROFILE_REJECT:
            default_rule = Rule(action="deny")
            logger.info("Using deny all rules")
        else:
            default_rule = Rule(action="allow")
            logger.info("Using allow all rules")

        rules = Rules(id=profile.name,
                      inbound_rules=[default_rule],
                      outbound_rules=[Rule(action="allow")])

        # Write rules to profile
        rules_path = RULES_PATH % {"profile_id": profile.name}
        self._datastore_client.etcd_client.write(
            rules_path, rules.to_json())

        logger.info('Finished applying rules.')


if __name__ == '__main__':
    configure_logger(logger=logger, 
                     logging_level=LOG_LEVEL,
                     log_file=PLUGIN_LOG,
                     root_logger=True)
    configure_logger(logger=pycalico_logger, 
                     logging_level=LOG_LEVEL,
                     log_file=PLUGIN_LOG,
                     root_logger=False)
    configure_logger(logger=util_logger, 
                     logging_level=LOG_LEVEL,
                     log_file=PLUGIN_LOG,
                     root_logger=False)

    mode = sys.argv[1]

    if mode == 'init':
        logger.info('No initialization work to perform')
    else:
        # These args only present for setup/teardown.
        namespace = sys.argv[2].replace('/', '_')
        pod_name = sys.argv[3].replace('/', '_')
        docker_id = sys.argv[4]

        logger.info('Args: %s' % sys.argv)
        logger.info("Using LOG_LEVEL=%s", LOG_LEVEL)
        logger.info("Using ETCD_AUTHORITY=%s", os.environ[ETCD_AUTHORITY_ENV])
        logger.info("Using CALICOCTL_PATH=%s", CALICOCTL_PATH)
        logger.info("Using KUBE_API_ROOT=%s", KUBE_API_ROOT)
        logger.info("Using CALICO_IPAM=%s", CALICO_IPAM)
        logger.info("Using CALICO_POLICY=%s", CALICO_POLICY)

        if mode == 'setup':
            logger.info('Executing Calico pod-creation hook')
            NetworkPlugin().create(namespace, pod_name, docker_id)
        elif mode == 'teardown':
            logger.info('Executing Calico pod-deletion hook')
            NetworkPlugin().delete(namespace, pod_name, docker_id)
        elif mode == 'status':
            logger.info('Executing Calico pod-status hook')
            NetworkPlugin().status(namespace, pod_name, docker_id)
