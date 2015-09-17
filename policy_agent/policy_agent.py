#!/usr/bin/python
import os
import sys
import time
import json
import Queue
import logging
import requests
import pycalico

from threading import Thread
from subprocess import check_output
from contextlib import closing
from pycalico.datastore_datatypes import Rules, Rule
from pycalico.datastore_errors import ProfileNotInEndpoint, ProfileAlreadyInEndpoint
from pycalico.datastore import DatastoreClient, PROFILE_PATH

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://localhost:8080/api/v1/')

ANNOTATION_NAMESPACE = "projectcalico.org/"
POLICY_ANNOTATION_KEY = "%spolicy" % ANNOTATION_NAMESPACE
EPID_ANNOTATION_KEY = "%sendpointID" % ANNOTATION_NAMESPACE
SVC_TYPE_ANNOTATION_KEY = "%stype" % ANNOTATION_NAMESPACE

POLICY_LOG_DIR = "/var/log/calico/calico-policy"
POLICY_LOG = "%s/calico-policy.log" % POLICY_LOG_DIR

LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

_log = logging.getLogger(__name__)
_datastore_client = DatastoreClient()


class PolicyAgent():

    """
    The Policy Agent is responsible for maintaining Watch Threads/Queues and internal resource lists
    """

    def __init__(self):
        self.q = Queue.Queue()
        self.pods = dict()
        self.services = dict()
        self.endpoints = dict()
        self.namespaces = dict()

        self.changed_pods = dict()
        self.changed_endpoints = dict()
        self.changed_namespaces = dict()

        self.PodWatcher = Thread(target=_keep_watch,
                                 args=(self.q, "pods"))
        self.SvcWatcher = Thread(target=_keep_watch,
                                 args=(self.q, "services"))
        self.NsWatcher = Thread(target=_keep_watch,
                                args=(self.q, "namespaces"))
        self.EptsWatcher = Thread(target=_keep_watch,
                                  args=(self.q, "endpoints"))

        self.PodWatcher.daemon = True
        self.SvcWatcher.daemon = True
        self.NsWatcher.daemon = True
        self.EptsWatcher.daemon = True

    def run(self):
        """
        PolicyAgent.run() is called at program init to spawn watch threads and parse their responses 
        """
        self.PodWatcher.start()
        self.SvcWatcher.start()
        self.NsWatcher.start()
        self.EptsWatcher.start()

        while True:
            self.read_responses()

    def read_responses(self):
        """
        Read Responses pulls a response off the Queue and processes it
        If no responses remain in the queue, it will trigger a resync for all resource lists
        """
        try:
            response = self.q.get_nowait()
            r_json = json.loads(response)
            r_type = r_json["type"]
            r_obj = r_json["object"]
            r_kind = r_obj["kind"]

            _log.info("%s: %s" % (r_type, r_kind))

            if r_kind in ["Pod", "Namespace", "Endpoints", "Service"]:
                if r_type == "DELETED":
                    self.delete_resource(kind=r_kind, target=r_obj)
                elif r_type in ["ADDED", "MODIFIED"]:
                    self.process_resource(
                        action=r_type, kind=r_kind, target=r_obj)
                else:
                    _log.error("Event from watch not recognized: %s" % r_type)

            else:
                _log.info(
                    "Resource %s not Pod, Service, Endpoints or Namespace" % r_kind)

        except Queue.Empty:
            self.resync()

    def process_resource(self, action, kind, target):
        """
        Takes a target object and an action and updates internal resource pools
        :param action: String of ["ADDED", "MODIFIED"] (returned by api watch)
        :param kind: String of ["Pod", "Namespace", "Service", "Endpoints"]
        :param target: json dict of resource info
        """
        # Determine Resource Pool
        if kind == "Pod":
            resource_pool = self.changed_pods
            obj = Pod(target)

        elif kind == "Service":
            # No intermediate processing on services
            resource_pool = self.services
            obj = Service(target)

        elif kind == "Endpoints":
            resource_pool = self.changed_endpoints
            obj = Endpoints(target)

        elif kind == "Namespace":
            resource_pool = self.changed_namespaces
            obj = Namespace(target)

        else:
            _log.error(
                "resource %s not Pod, Service, Endpoints or Namespace" % kind)
            return

        target_key = obj.key

        if action == "ADDED":
            if target_key not in resource_pool:
                resource_pool[target_key] = obj
                _log.info("%s %s added to Calico store" % (kind, target_key))

            else:
                _log.error("Tried to Add %s %s, but it was already in bin" %
                           (kind, target_key))

        elif action == "MODIFIED":
            if target_key in resource_pool:
                _log.info("Updating %s %s" % (kind, target_key))
                resource_pool[target_key] = obj

            else:
                _log.warning("Tried to Modify %s %s, but it was not in bin. "
                             "Treating as Addition" %
                             (kind, target_key))
                self.process_resource(action="ADDED", kind=kind, target=target)

        else:
            _log.error("Event in process_resource not recognized: %s" % r_type)

    def delete_resource(kind, target):
        if kind == "Pod":
            resource_pool = self.pods
            obj = Pod(target)

        elif kind == "Service":
            resource_pool = self.services
            obj = Service(target)

        elif kind == "Endpoints":
            resource_pool = self.endpoints
            obj = Endpoints(target)

        elif kind == "Namespace":
            resource_pool = self.namespaces
            obj = Namespace(target)

        target_key = obj.key

        if target_key in resource_pool:
            del resource_pool[target_key]
            _log.info("%s %s deleted from Calico store" % (kind, target_key))

        else:
            _log.error(
                "Tried to Delete %s %s but it was not in bin" %
                (kind, target_key))

    def match_pod(self, namespace, name):
        try:
            return self.pods["%s/%s" % (namespace, name)]
        except KeyError:
            _log.error("Pod %s in NS %s not processed" % (name, namespace))
            return None

    def resync(self):
        """
        Updates Calico store with new resource information
        """
        # Create/update Namespace Profiles
        for namespace_key, ns in self.changed_namespaces.items():
            if ns.create_ns_profile():
                self.namespaces[namespace_key] = ns
                del self.changed_namespaces[namespace_key]

        # Apply Namespace policy to new/updated pods
        for pod_key, po in self.changed_pods.items():
            if po.apply_ns_policy():
                if po.remove_default_profile():
                    self.pods[pod_key] = po
                    del self.changed_pods[pod_key]

        # As endpoint lists change, create/add new profiles to pods as
        # necessary
        for ep_key, ep in self.changed_endpoints.items():

            # Get policy of the Service and namespace. Uses same namespace/name
            # dict key.
            try:
                svc_policy = self.services[ep_key].type
            except KeyError:
                _log.warning("Service %s not yet in store" % ep_key)
                continue

            try:
                ns_policy = self.namespaces[ep.namespace].policy
            except KeyError, AttributeError:
                _log.warning("Namespace %s not yet in store" % ep.namespace)
                continue

            # if namespace is open, or svc is closed, do nothing
            if ns_policy == "open" or svc_policy == "closed":
                self.endpoints[ep_key] = ep
                del self.changed_endpoints[ep_key]

            # else define service policy
            else:
                # find pods and append profiles
                for association in ep.generate_svc_profile_pod_list():
                    profiles = association[0]
                    for pod in association[1]:
                        existing_pod = self.match_pod(
                            namespace=ep.namespace, name=pod)
                        if existing_pod:
                            _log.info("Adding profiles %s to pod %s" % (profiles, existing_pod))
                            try:
                                _datastore_client.append_profiles_to_endpoint(profile_names=profiles,
                                                                              endpoint_id=existing_pod.ep_id)
                            except ProfileAlreadyInEndpoint:
                                _log.warning(
                                    "Apply %s to Pod %s : Profile Already exists" % (profiles, existing_pod.key))


                # declare Endpoints obj processed
                self.endpoints[ep_key] = ep
                del self.changed_endpoints[ep_key]


class Resource():

    """
    Resource objects pull pertinent info from json blobs and maintain universal functions  
    """

    def __init__(self, json):
        """
        On init, each Resource saves the raw json, pulls necessary info (unique), 
        and defines a unique key identifier
        """
        self.json = json
        self.from_json(json)
        self.key = self.get_key()

    def from_json(self, json):
        self.name = "noop"
        return

    def get_key(self):
        return self.name

    def __str__(self):
        return "%s: %s\n%s" % (self.kind, self.key, self.json)


class Pod(Resource):

    def from_json(self, json):
        self.kind = "Pod"
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        try:
            self.ep_id = json["metadata"]["annotations"][EPID_ANNOTATION_KEY]
        except KeyError:
            # If the annotations do not contain a Calico endpoint, it is likely because the plugin
            # hasn't processed this pod yet.
            _log.warning(
                "Pod %s does not yet have a Calico Endpoint" % self.get_key())
            self.ep_id = None

    def get_key(self):
        return "%s/%s" % (self.namespace, self.name)

    def apply_ns_policy(self):
        ns_tag = "namespace_%s" % self.namespace

        if _datastore_client.profile_exists(ns_tag) and self.ep_id:
            try:
                _datastore_client.append_profiles_to_endpoint(profile_names=[ns_tag],
                                                              endpoint_id=self.ep_id)
            except ProfileAlreadyInEndpoint:
                _log.warning(
                    "Apply %s to Pod %s : Profile Already exists" % (ns_tag, self.key))
                pass
            return True
        else:
            _log.error("Pod Resource %s found before Namespace Resource %s" % (
                self.name, self.namespace))
            return False

    def remove_default_profile(self):
        """
        remove the default reject all rule programmed by the plugin
        """
        default_profile = "REJECT_ALL"
        try:
            _log.info("Removing Default Profile")
            _datastore_client.remove_profiles_from_endpoint(profile_names=[default_profile],
                                                            endpoint_id=self.ep_id)
            return True
        except ProfileNotInEndpoint:
            _log.info("Default Profile not on Endpoint")
            return True
        else:
            _log.info("Default Profile Removal Failed")
            return False


class Service(Resource):

    def from_json(self, json):
        self.kind = "Service"
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        try:
            self.type = json["metadata"]["annotations"][SVC_TYPE_ANNOTATION_KEY]
        except KeyError:
            _log.warning("Service Type not specified assuming closed")
            self.type = "closed"

    def get_key(self):
        return "%s/%s" % (self.namespace, self.name)


class Endpoints(Resource):

    def from_json(self, json):
        self.kind = "Endpoints"
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        self.subsets = json["subsets"]

    def get_key(self):
        return "%s/%s" % (self.namespace, self.name)

    def generate_svc_profile_pod_list(self):
        """
        Endpoints objects contain a list of subsets
        containing pod and policy info
        subsets: [
            {
                addresses: [
                    ...pods...
                ],
                ports: [
                    ...associated ports...
                ]
            },
            {
                addresses: [
                    ...pods...
                ],
                ports: [
                    ...associated ports...
                ]
            },
        ]
        :return: A generated list of pod-profile associations
        :rtype: a list of structs each containing
                a list of profiles and a list of assoc pods
                list( struct(list(str), list(str)) )
        e.g. [([prof1, prof2], [pod1, pod2]), ([prof3], [pod1])]
        """
        def verify_args(ports_obj, try_arg):
            try:
                arg = ports_obj[try_arg]
            except KeyError:
                arg = None
            return arg

        self.association_list = list()
        for subset in self.subsets:

            # Generate a list of new svc profiles per port spec
            profiles = list()
            for port_spec in subset["ports"]:
                dst_port = verify_args(port_spec, "port")
                protocol = verify_args(port_spec, "protocol")

                # Create Profile for port spec
                prof_name = "svc_%s_%s_port_%s" % (
                    self.namespace, self.name, dst_port)
                if not _datastore_client.profile_exists(prof_name):
                    profile_path = PROFILE_PATH % {"profile_id": prof_name}
                    _datastore_client.etcd_client.write(
                        profile_path + "tags", '["%s"]' % prof_name)

                    # Determine rule set
                    default_allow = Rule(action="allow")
                    rules = Rules(id=prof_name,
                                  inbound_rules=[Rule(action="allow",
                                                      dst_ports=[dst_port],
                                                      protocol=protocol)],
                                  outbound_rules=[default_allow])

                    # Write rules to profile
                    _datastore_client.etcd_client.write(
                        profile_path + "rules", rules.to_json())

                profiles.append(prof_name)

            # Generate list of pod names
            pods = list()
            for pod in subset["addresses"]:
                pods.append(pod["targetRef"]["name"])

            self.association_list.append((profiles, pods))

        _log.info("association list:\n%s" % self.association_list)
        return self.association_list


class Namespace(Resource):

    def from_json(self, json):
        self.kind = "Namespace"
        self.name = json["metadata"]["name"]

        try:
            self.policy = json["metadata"][
                "annotations"][POLICY_ANNOTATION_KEY]
        except KeyError:
            _log.warning("Namespace does not have policy, assumed closed")
            self.policy = "closed"

    def get_key(self):
        return self.name

    def create_ns_profile(self):
        # Derive NS tag
        ns_tag = "namespace_%s" % self.name

        # Add Tags
        profile_path = PROFILE_PATH % {"profile_id": ns_tag}
        _datastore_client.etcd_client.write(
            profile_path + "tags", '["%s"]' % ns_tag)

        # Determine rule set based on policy
        default_allow = Rule(action="allow")

        if self.policy == "open":
            rules = Rules(id=ns_tag,
                          inbound_rules=[default_allow],
                          outbound_rules=[default_allow])
            _log.info("Applying Open Rules to NS Profile %s" % ns_tag)

        elif self.policy == "closed":
            rules = Rules(id=ns_tag,
                          inbound_rules=[Rule(action="allow", src_tag=ns_tag)],
                          outbound_rules=[default_allow])
            _log.info("Applying Closed Rules to NS Profile %s" % ns_tag)

        else:
            _log.error(
                "Namespace %s policy is neither open nor closed" % self.name)
            return False

        # Write rules to profile
        _datastore_client.etcd_client.write(
            profile_path + "rules", rules.to_json())
        return True

    def delete_ns_profile(self):
        # Derive NS tag
        ns_tag = "namespace_%s" % self.name

        # Remove from Store
        _datastore_client.remove_profile(ns_tag)
        return True


def _keep_watch(queue, resource):
    """
    Called by watcher threads. Adds watch events to Queue
    """
    response = _get_api_stream(resource)
    for line in response.iter_lines():
        if line:
            queue.put(line)


def _get_api_token():
    """
    Get the kubelet Bearer token for this node, used for HTTPS auth.
    If no token exists, this method will return an empty string.
    :return: The token.
    :rtype: str
    """
    try:
        with open('/var/lib/kubelet/kubernetes_auth') as f:
            json_string = f.read()
    except IOError as e:
        return ""

    auth_data = json.loads(json_string)
    return auth_data['BearerToken']


def _get_api_stream(resource):
    """
    Watch a stream from the API given a resource.

    :param resource: The plural resource you would like to watch.
    :return: A stream of json objs e.g. {"type": "MODIFED"|"ADDED"|"DELETED", "object":{...}}
    :rtype stream
    """
    path = "watch/%s" % resource
    _log.info(
        'Streaming API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token})
    session = requests.Session()
    return session.get("%s%s" % (KUBE_API_ROOT, path),
                       verify=False, stream=True)


def _get_api_obj(namespace, resource, name):
    """
    Get a resource from the API specified API path.
    e.g.
    _get_api_path(default, service, nginx)

    :param namespace:
    :param resource: plural resource type
    :param name:
    :return: A JSON API object
    :rtype json dict
    """
    path = "namespaces/%s/%s/%s" % (namespace, resource, name)
    _log.info(
        'Getting API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token})
    response = session.get(KUBE_API_ROOT + path, verify=False)
    return json.loads(response.text)


if __name__ == '__main__':

    if not os.path.exists(POLICY_LOG_DIR):
        os.makedirs(POLICY_LOG_DIR)

    hdlr = logging.FileHandler(filename=POLICY_LOG)
    hdlr.setFormatter(logging.Formatter(LOG_FORMAT))
    _log.addHandler(hdlr)
    _log.setLevel(LOG_LEVEL)

    app = PolicyAgent()
    app.run()
