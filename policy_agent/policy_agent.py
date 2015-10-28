#!/usr/bin/python
import time
import json
import Queue
import logging
from threading import Thread

import requests

import common
from common.constants import *
from common.util import configure_logger, _get_api_stream, _get_api_list
import pycalico
from pycalico.datastore_datatypes import Rules, Rule, Profile
from pycalico.datastore_errors import ProfileNotInEndpoint, ProfileAlreadyInEndpoint
from pycalico.datastore import DatastoreClient

KIND_NAMESPACE = "Namespace"
KIND_SERVICE = "Service"
KIND_POD = "Pod"
KIND_ENDPOINTS = "Endpoints"
VALID_KINDS = [KIND_NAMESPACE, KIND_SERVICE, KIND_POD, KIND_ENDPOINTS]

CMD_ADDED = "ADDED"
CMD_MODIFIED = "MODIFIED"
CMD_DELETED = "DELETED"
VALID_COMMANDS = [CMD_ADDED, CMD_MODIFIED, CMD_DELETED]

logger = logging.getLogger(__name__)
util_logger = logging.getLogger(common.util.__name__)
pycalico_logger = logging.getLogger(pycalico.__name__)

_datastore_client = DatastoreClient()


class PolicyAgent():

    """
    The Policy Agent is responsible for maintaining Watch Threads/Queues and internal resource lists.
    """

    def __init__(self):
        self.watcher_queue = Queue.Queue()

        self.namespaces = {}
        self.services = {}
        self.pods = {}
        self.endpoints = {}

        self.changed_namespaces = {}
        self.changed_services = {}
        self.changed_pods = {}
        self.changed_endpoints = {}

        self.namespace_watcher = None
        self.service_watcher = None
        self.pod_watcher = None
        self.endpoints_watcher = None

        self.init_lists()
        self.init_threads()

    def run(self):
        """
        PolicyAgent.run() is called at program init to spawn watch threads,
        Loops to read responses from the _watcher Queue as they come in.
        """
        self.pod_watcher.start()
        self.service_watcher.start()
        self.namespace_watcher.start()
        self.endpoints_watcher.start()

        self.read_updates()

    def init_lists(self):
        """
        Pull the initial list of existing resources and grabs the current Resource Version
        for watcher use.
        """
        logger.info("Initializing Resource Lists")
        initNamespaces = _get_api_list("namespaces")
        initServices = _get_api_list("services")
        initPods = _get_api_list("pods")
        initEndpoints = _get_api_list("endpoints")

        for ns in initNamespaces["items"]:
            self.process_resource(command=CMD_ADDED,
                                  kind=KIND_NAMESPACE,
                                  resource_json=ns)

        for svc in initServices["items"]:
            self.process_resource(command=CMD_ADDED,
                                  kind=KIND_SERVICE,
                                  resource_json=svc)

        for pod in initPods["items"]:
            self.process_resource(command=CMD_ADDED,
                                  kind=KIND_POD,
                                  resource_json=pod)

        for ep in initEndpoints["items"]:
            self.process_resource(command=CMD_ADDED,
                                  kind=KIND_ENDPOINTS,
                                  resource_json=ep)

        self.nsResourceVersion = initEndpoints["metadata"]["resourceVersion"]
        self.svcResourceVersion = initServices["metadata"]["resourceVersion"]
        self.podResourceVersion = initPods["metadata"]["resourceVersion"]
        self.epResourceVersion = initNamespaces["metadata"]["resourceVersion"]

        logger.info("Service Resource Version = %s" % self.svcResourceVersion)
        logger.info("Namespace Resource Version = %s" % self.nsResourceVersion)
        logger.info("Pod Resource Version = %s" % self.podResourceVersion)
        logger.info("Endpoints Resource Version = %s" % self.epResourceVersion)

    def init_threads(self):
        # Assert these have not been initialized yet.
        assert not self.namespace_watcher
        assert not self.service_watcher
        assert not self.pod_watcher
        assert not self.endpoints_watcher

        self.namespace_watcher = Thread(target=_keep_watch,
                                        args=(self.watcher_queue, "namespaces", self.nsResourceVersion))
        self.service_watcher = Thread(target=_keep_watch,
                                      args=(self.watcher_queue, "services", self.svcResourceVersion))
        self.pod_watcher = Thread(target=_keep_watch,
                                  args=(self.watcher_queue, "pods", self.podResourceVersion))
        self.endpoints_watcher = Thread(target=_keep_watch,
                                        args=(self.watcher_queue, "endpoints", self.epResourceVersion))

        self.namespace_watcher.daemon = True
        self.service_watcher.daemon = True
        self.pod_watcher.daemon = True
        self.endpoints_watcher.daemon = True

    def read_updates(self):
        """
        Continuous Function:
        Pulls an update off the Queue and processes it.
        If no responses remain in the queue, and pending lists are not empty,
        it will trigger a resync for all resource lists.
        """
        update = None

        while True:
            try:
                if not update:
                    # Get next update, if EOQ, raise Queue.Empty
                    update = self.watcher_queue.get_nowait()
                logger.debug("Recieved Update: %s", update)
                raw_json = json.loads(update)
                command = raw_json["type"]
                resource_json = raw_json["object"]
                kind = resource_json["kind"]

                logger.debug("Reading update %s: %s" % (resource_json, kind))

                if command == CMD_DELETED:
                    self.delete_resource(kind=kind, resource_json=resource_json)
                elif command in [CMD_ADDED, CMD_MODIFIED]:
                    self.process_resource(command=command,
                                          kind=kind,
                                          resource_json=resource_json)
                update = None

            except Queue.Empty, ValueError:
                # If Queue is empty and Pending Changes exist, resync.
                if self.changed_namespaces or self.changed_services or self.changed_pods or self.changed_endpoints:
                    self.resync()
                else:
                    # If there is no work to do, wait for next update.
                    update = self.watcher_queue.get()

    def process_resource(self, command, kind, resource_json):
        """
        Takes a resource_json object and an command and updates internal resource pools
        :param command: String of [CMD_ADDED, CMD_MODIFIED] (returned by api watch)
        :param kind: String in VALID_KINDS
        :param resource_json: json dict of resource info
        """
        assert command in VALID_COMMANDS, "Invalid Command %s" % command
        assert kind in VALID_KINDS, "Invalid Kind %s" % kind

        # Determine Resource Pool
        if kind == KIND_NAMESPACE:
            pending_updates = self.changed_namespaces
            resource = Namespace(resource_json)
        elif kind == KIND_SERVICE:
            pending_updates = self.changed_services
            resource = Service(resource_json)
        elif kind == KIND_POD:
            pending_updates = self.changed_pods
            resource = Pod(resource_json)
        elif kind == KIND_ENDPOINTS:
            pending_updates = self.changed_endpoints
            resource = Endpoints(resource_json)

        resource.key = resource.key

        if command == CMD_ADDED:
            if resource.key not in pending_updates:
                pending_updates[resource.key] = resource
                logger.info("%s %s added to Calico store" % (kind, resource.key))
            else:
                logger.error("Tried to Add %s %s, but it was already in bin" %
                           (kind, resource.key))
        elif command == CMD_MODIFIED:
            if resource.key in pending_updates:
                logger.info("Updating %s %s" % (kind, resource.key))
                pending_updates[resource.key] = resource
            else:
                logger.warning("Tried to Modify %s %s, but it was not in bin. "
                             "Treating as Addition" % (kind, resource.key))
                self.process_resource(command=CMD_ADDED,
                                      kind=kind,
                                      resource_json=resource_json)
        else:
            logger.error("Event in process_resource not recognized: %s" % r_type)

    def delete_resource(self, kind, resource_json):
        """
        Takes a resource_json object and an command and deletes it from internal resource pools
        :param kind: String in VALID_KINDS
        :param resource_json: json dict of resource info
        """
        assert kind in VALID_KINDS, "Invalid Kind %s" % kind

        if kind == KIND_NAMESPACE:
            resource_list = self.namespaces
            resource = Namespace(resource_json)

        elif kind == KIND_SERVICE:
            resource_list = self.services
            resource = Service(resource_json)

        elif kind == KIND_POD:
            resource_list = self.pods
            resource = Pod(resource_json)

        elif kind == KIND_ENDPOINTS:
            resource_list = self.endpoints
            resource = Endpoints(resource_json)

        if resource.key in resource_list:
            del resource_list[resource.key]
            logger.info("%s %s deleted from Calico store" % (kind, resource.key))

        else:
            logger.error("Tried to Delete %s %s but it was not in bin" %
                       (kind, resource.key))

    def resync(self):
        """
        Updates Calico store with new resource information
        """
        logger.info("Starting Resync")
        for namespace_key, ns in self.changed_namespaces.items():
            logger.info("Processing Namespace %s" % namespace_key)

            # Create/update Namespace Profiles.
            ns.create_profile()
            self.nsResourceVersion = ns.resourceVersion
            self.namespaces[namespace_key] = ns
            del self.changed_namespaces[namespace_key]

        for service_key, svc in self.changed_services.items():
            logger.info("Processing Service %s" % service_key)

            # Process Services.
            self.svcResourceVersion = svc.resourceVersion
            self.services[service_key] = svc
            del self.changed_services[service_key]

        for pod_key, pod in self.changed_pods.items():
            logger.info("Processing Pod %s" % pod_key)

            # Apply Namespace policy to new/updated pods.
            namespace = self.namespaces.get(pod.namespace)
            if not namespace:
                logger.warning("Namespace %s not yet processed" % pod.namespace)
                continue

            pod.append_profile(namespace.profile_name)
            pod.remove_profile(DEFAULT_PROFILE_REJECT)

            self.podResourceVersion = pod.resourceVersion
            self.pods[pod_key] = pod
            del self.changed_pods[pod_key]

        # As endpoint lists change, create/add new profiles to pods as
        # necessary
        # TODO: if some object not ready for resync, finish loop w/out moving to
        # processed list
        for ep_key, ep in self.changed_endpoints.items():
            logger.info("Processing Endpoints %s" % ep_key)

            # Get policy of the Service and namespace. Uses same namespace/name
            # dict key.
            namespace = self.namespaces.get(ep.namespace)
            service = self.services.get(ep_key)

            if not service:
                logger.warning("Service %s not yet in store" % ep_key)
                continue

            if not service:
                logger.warning("Namespace %s not yet in store" % ep.namespace)
                continue

            logger.info("Using Service policy %s and Namespace policy %s" %
                      (service.policy, namespace.policy))

            if namespace.policy == POLICY_OPEN or service.policy == POLICY_CLOSED:
                # If namespace is open, or svc is closed, do nothing.
                # NamespaceIP services can only exists in Closed namespaces,
                # in which case NamespaceIP service policy is redundant.
                # When the Namespace is open, all valid service types are open as well.
                logger.debug("No Endpoints work to do.")
                self.endpoints[ep_key] = ep
                del self.changed_endpoints[ep_key]
            else:
                # Namespace is Closed, but Service is Open, we need to create an open profile
                # for the Open Ports
                logger.debug("Defining Service Policy.")
                ep.generate_svc_profiles_pods()

                for profile, pod_names in ep.service_profiles.items():
                    # Find pods and append profiles.
                    for pod_name in pod_names:
                        pod = self.pods.get("%s/%s" % (ep.namespace, pod_name))
                        if pod:
                            pod.append_profile(profile)
                        else:
                            logger.warning("Pod %s is not yet processed" % pod_name)

                # Declare Endpoints as processed.
                self.epResourceVersion = ep.resourceVersion
                self.endpoints[ep_key] = ep
                del self.changed_endpoints[ep_key]

        logger.info("Finished Resync")


class Resource():
    """
    The Resource class is an abstract super class which represents Kubernetes API objects.
    The class defines a number of abstract methods which must be implemented in subclasses.
    """

    def __init__(self, json):
        """
        On init, each Resource saves the raw json, pulls necessary info (unique),
        and defines a unique key identifier
        """
        logger.debug(json)
        self._json = json
        self.init_from_json(json)
        self.resourceVersion = json["metadata"]["resourceVersion"]

    def init_from_json(self, json):
        """
        Abstract Method.
        Sets public variables relevant to the child Resource.
        """
        raise NotImplementedError("init_from_json not implemented.")

    @property
    def key(self):
        """
        Abstract method.
        Determines a unique identifier for the Resource
        """
        raise NotImplementedError("@property key not implemented.")

    def __str__(self):
        return "%s: %s\n%s" % (self.kind, self.key, self._json)


class Namespace(Resource):

    def init_from_json(self, json):
        self.kind = KIND_NAMESPACE
        self.name = json["metadata"]["name"]
        self.profile_name = "namespace_%s" % self.name

        try:
            self.policy = json["metadata"]["labels"]["projectcalico.org/policy"]
        except KeyError:
            logger.warning("Namespace does not have policy, assumed Open")
            self.policy = POLICY_OPEN

    @property
    def key(self):
        return self.name

    def create_profile(self):
        """
        Generates an Open or Closed policy profile based on the Namespace's networkPolicy
        """
        namespace_profile = Profile(self.profile_name)
        namespace_profile.tags.update([self.profile_name])

        # Determine rule set based on policy
        logger.info("Creating profile %s with %s rules", self.profile_name, self.policy)
        default_allow = Rule(action="allow")
        if self.policy == POLICY_OPEN:
            namespace_profile.rules = Rules(id=self.profile_name,
                                            inbound_rules=[default_allow],
                                            outbound_rules=[default_allow])
            logger.info("Applying Open Rules to NS Profile %s" % self.profile_name)
        elif self.policy == POLICY_CLOSED:
            namespace_profile.rules = Rules(id=self.profile_name,
                                            inbound_rules=[Rule(action="allow",
                                                                src_tag=self.profile_name),
                                                           Rule(action="allow",
                                                                src_tag=CALICO_SYSTEM)],
                                            outbound_rules=[default_allow])
            logger.info("Applying Closed Rules to NS Profile %s" % self.profile_name)

        # Write rules and tags to profile
        _datastore_client.profile_update_tags(namespace_profile)
        _datastore_client.profile_update_rules(namespace_profile)


class Service(Resource):

    def init_from_json(self, json):
        self.kind = KIND_SERVICE
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        try:
            self.policy = json["metadata"]["labels"]["projectcalico.org/policy"]
        except KeyError:
            logger.warning("Service does not have policy, assumed Open")
            self.policy = POLICY_OPEN

    @property
    def key(self):
        return "%s/%s" % (self.namespace, self.name)


class Pod(Resource):

    def init_from_json(self, json):
        self.kind = KIND_POD
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        try:
            self.ep_id = json["metadata"]["annotations"][EPID_ANNOTATION_KEY]
        except KeyError:
            # If the annotations do not contain a Calico endpoint, it is likely because the plugin
            # hasn't processed this pod yet.
            logger.warning("Pod %s does not yet have a Calico Endpoint" % self.key)
            self.ep_id = None

    @property
    def key(self):
        return "%s/%s" % (self.namespace, self.name)

    def append_profile(self, profile_name):
        """
        Add profile to endpoint self.ep_id
        """
        logger.info("Adding profile %s to Pod %s" % (profile_name, self.key))
        if not _datastore_client.profile_exists(profile_name):
            logger.warning("Profile %s does not exist" % profile_name)

        if self.ep_id:
            try:
                _datastore_client.append_profiles_to_endpoint(profile_names=[profile_name],
                                                              endpoint_id=self.ep_id)
            except ProfileAlreadyInEndpoint:
                logger.debug("Profile %s Already exists", profile_name)
        else:
            logger.warning("Pod %s does not have a Calico Endpoint", self.key)


    def remove_profile(self, profile_name):
        """
        Remove profile from endpoint self.ep_id
        """
        logger.info("Removing profile %s to Pod %s" % (profile_name, self.key))
        if self.ep_id:
            try:
                _datastore_client.remove_profiles_from_endpoint(profile_names=[profile_name],
                                                                endpoint_id=self.ep_id)
            except ProfileNotInEndpoint:
                logger.warning("Profile %s not on Endpoint", profile_name)
        else:
            logger.warning("Pod %s does not have a Calico Endpoint", self.key)

class Endpoints(Resource):

    def init_from_json(self, json):
        self.kind = KIND_ENDPOINTS
        self.name = json["metadata"]["name"]
        self.namespace = json["metadata"]["namespace"]
        self.subsets = json["subsets"]

    @property
    def key(self):
        return "%s/%s" % (self.namespace, self.name)

    def generate_svc_profiles_pods(self):
        """
        Endpoints objects contain a list of subsets containing pod and policy info.
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
        :return: A generated dict of profile-pod associations.
        :rtype: a dict of profiles mapping to a list of associated pods.
        """
        self.service_profiles = {}
        for subset in self.subsets:
            profile_name = "%s_svc_%s" % (self.namespace, self.name)

            # Generate a list of new svc profiles per port spec.
            port_rules = []
            for port_spec in subset["ports"]:
                dst_port = port_spec.get("port")
                protocol = port_spec.get("protocol")

                if protocol and dst_port:
                    port_rules.append(Rule(action="allow",
                                           dst_ports=[dst_port],
                                           protocol=protocol.lower()))
                    profile_name += "_%s%s" % (protocol, dst_port)
                else:
                    logger.warning("Protocol or dst_port not found in Port Spec")

            # Create Profile for the subset.
            if not _datastore_client.profile_exists(profile_name):
                logger.info("Creating Profile %s" % profile_name)
                service_profile = Profile(profile_name)

                # Determine rule set.
                default_allow = Rule(action="allow")
                service_profile.rules = Rules(id=profile_name,
                                              inbound_rules=port_rules,
                                              outbound_rules=[default_allow])

                # Create Profile with rules.
                _datastore_client.profile_update_rules(service_profile)
            else:
                logger.warning("Profile %s already exists" % profile_name)

            # Generate list of pod names.
            pods = []
            for pod in subset["addresses"]:
                try:
                    pods.append(pod["targetRef"]["name"])
                except KeyError:
                    logger.debug("Subset Address %s has no targetRef" % pod)

            self.service_profiles[profile_name] = pods

        logger.debug("Service Profiles:\n%s" % self.service_profiles)


def _keep_watch(queue, resource, resource_version):
    """
    Called by watcher threads. Adds watch events to Queue
    """
    while True:
        try:
            response = _get_api_stream(resource, resource_version)
            for line in response.iter_lines():
                if line:
                    queue.put(line)
        except:
            # If we hit an exception attempting to watch this path, log it, and retry the watch
            # after a short sleep in order to prevent tight-looping.  We catch all BaseExceptions
            # so that the thread never dies.
            logger.exception("Exception watching path %s", resource)
            time.sleep(10)


if __name__ == '__main__':

    configure_logger(logger=logger,
                     log_level=LOG_LEVEL,
                     log_to_stdout=False,
                     log_format=ROOT_LOG_FORMAT,
                     log_file=POLICY_LOG)
    configure_logger(logger=pycalico_logger,
                     log_level=LOG_LEVEL,
                     log_to_stdout=False,
                     log_format=LOG_FORMAT,
                     log_file=POLICY_LOG)
    configure_logger(logger=util_logger,
                     log_level=LOG_LEVEL,
                     log_to_stdout=False,
                     log_format=LOG_FORMAT,
                     log_file=POLICY_LOG)

    try:
        PolicyAgent().run()
    except BaseException:
        # Log the exception
        logger.exception("Unhandled Exception killed agent")
