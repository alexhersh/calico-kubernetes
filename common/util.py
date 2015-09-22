import os
import sys
import json
import logging
import requests

from common.constants import KUBE_API_ROOT, KUBERNETES_LOG_DIR

logger = logging.getLogger(__name__)

ROOT_LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s %(process)d %(levelname)s %(filename)s: %(message)s'

def configure_logger(logger, logging_level, log_file, root_logger=False):
    """
    Configures logging to the file 'calico.log' in the specified log directory

    If the logs are not coming from calico_kubernetes.py, format the log to
     include the filename of origin

    :param logger: logger object to configure
    :param logging_level: level at which logger starts logging. Input type is lowercase string
    :param root_logger: True indicated logger is calico_kubernetes. False indicates otherwise
    :param log_dir: Directory where calico.log lives. If None set to default
    :return:
    """
    if not os.path.exists(KUBERNETES_LOG_DIR):
        os.makedirs(KUBERNETES_LOG_DIR)

    hdlr = logging.FileHandler(filename=log_file)

    if root_logger:
        formatter = logging.Formatter(ROOT_LOG_FORMAT)
        hdlr.setFormatter(formatter)
    else:
        formatter = logging.Formatter(LOG_FORMAT)
        hdlr.setFormatter(formatter)

    logger.addHandler(hdlr)
    logger.setLevel(logging_level)


def _get_api_token():
    """
    Get the kubelet Bearer token for this node, used for HTTPS auth.
    If no token exists, this method will return an empty string.
    :return: The token.
    :rtype: str
    """
    logger.info('Getting Kubernetes Authorization')

    try:
        with open('/var/lib/kubelet/kubernetes_auth') as f:
            json_string = f.read()
    except IOError as e:
        logger.warning("Failed to open auth_file (%s). Assuming insecure mode", e)
        if _api_root_secure():
            logger.error("Cannot use insecure mode. API root is set to"
                         "secure (%s). Exiting", KUBE_API_ROOT)
            sys.exit(1)
        else:
            return ""

    logger.info('Got kubernetes_auth: ' + json_string)
    auth_data = json.loads(json_string)
    return auth_data['BearerToken']


def _api_root_secure():
    """
    Checks whether the KUBE_API_ROOT is secure or insecure.
    If not an http or https address, exit.

    :return: Boolean: True if secure. False if insecure
    """
    if (KUBE_API_ROOT[:5] == 'https'):
        return True
    elif (KUBE_API_ROOT[:5] == 'http:'):
        return False
    else:
        logger.error('KUBE_API_ROOT is not set correctly (%s). Please specify '
                     'a http or https address. Exiting', KUBE_API_ROOT)
        sys.exit(1)


def _patch_api(path, patch):
    """
    Patch an api resource to a given path

    :param path: The relative path to an API endpoint.
    :param patch: The updated data
    :return: A list of JSON API objects
    :rtype list
    """
    logger.debug('Patching API Resource in path %s with data %s', path, patch)
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token,
                            'Content-type': 'application/strategic-merge-patch+json'})
    response = session.patch(url=KUBE_API_ROOT+path, data=patch, verify=True)
    return json.loads(response.text)


def _get_api_stream(resource, resource_version):
    """
    Watch a stream from the API given a resource.

    :param resource: The plural resource you would like to watch.
    :return: A stream of json objs e.g. {"type": "MODIFED"|"ADDED"|"DELETED", "object":{...}}
    :rtype stream
    """
    path = "watch/%s?resourceVersion=%s" % (resource, resource_version)
    logger.info(
        'Streaming API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token})
    session = requests.Session()
    return session.get("%s%s" % (KUBE_API_ROOT, path),
                       verify=False, stream=True)


def _get_api_list(resource):
    """
    Get a resource from the API specified API path.
    e.g.
    _get_api_list(default, services)

    :param resource: plural resource type
    :return: A JSON API object
    :rtype json dict
    """
    logger.info(
        'Getting API Resource: %s from KUBE_API_ROOT: %s', resource, KUBE_API_ROOT)
    bearer_token = _get_api_token()
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + bearer_token})
    response = session.get(KUBE_API_ROOT + resource, verify=False)
    return json.loads(response.text)