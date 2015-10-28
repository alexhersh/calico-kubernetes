import os
import sys
import json
import logging
import requests
from cloghandler import ConcurrentRotatingFileHandler

from common.constants import *

logger = logging.getLogger(__name__)


class IdentityFilter(logging.Filter):
    """
    Filter class to impart contextual identity information onto loggers.
    """
    def __init__(self, identity):
        self.identity = identity

    def filter(self, record):
        record.identity = self.identity
        return True


def configure_logger(logger, log_level, log_format=LOG_FORMAT,
                     log_to_stdout=True, log_file=PLUGIN_LOG):
    """
    Configures logging to the file 'calico.log' in the specified log directory
    If the logs are not coming from calico_kubernetes.py, format the log to
     include the filename of origin
    Additionally configures a stdout handler which logs INFO and
    above to stdout.
    :param logger: logger object to configure
    :param log_level: level at which logger starts logging.
    :param log_format: Indicates which logging scheme to use.
    :param log_to_stdout: If True, configure the stdout stream handler.
    :param log_dir: Directory where calico.log lives. If None set to default
    :return:
    """
    if not os.path.exists(os.path.dirname(log_file)):
        os.makedirs(os.path.dirname(log_file))

    formatter = logging.Formatter(log_format)

    file_hdlr = ConcurrentRotatingFileHandler(filename=log_file,
                                              maxBytes=1000000,
                                              backupCount=5)
    file_hdlr.setFormatter(formatter)

    logger.addHandler(file_hdlr)
    logger.setLevel(log_level)

    # Create an stdout handler and apply it to the logger
    if log_to_stdout:
        stdout_hdlr = logging.StreamHandler(sys.stdout)
        stdout_hdlr.setLevel(log_level)
        stdout_hdlr.setFormatter(formatter)
        logger.addHandler(stdout_hdlr)


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
    session = requests.Session()
    if KUBE_AUTH_TOKEN:
        session.headers.update({'Authorization': 'Bearer ' + KUBE_AUTH_TOKEN})
    session.headers.update({'Content-type': 'application/merge-patch+json'})
    response = session.patch(url=KUBE_API_ROOT+path, data=patch, verify=False)
    return json.loads(response.text)


def _get_api_stream(resource, resource_version):
    """
    Watch a stream from the API given a resource.

    :param resource: The plural resource you would like to watch.
    :return: A stream of json objs e.g. {"type": "MODIFED"|"ADDED"|"DELETED", "object":{...}}
    :rtype stream
    """
    path = "watch/%s?resourceVersion=%s" % (resource, resource_version)
    logger.debug(
        'Streaming API Resource: %s from KUBE_API_ROOT: %s', path, KUBE_API_ROOT)
    session = requests.Session()
    if KUBE_AUTH_TOKEN:
        logger.debug("Using Auth Token: %s", KUBE_AUTH_TOKEN)
        session.headers.update({'Authorization': 'Bearer ' + KUBE_AUTH_TOKEN})
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
    logger.debug(
        'Getting API Resource: %s from KUBE_API_ROOT: %s', resource, KUBE_API_ROOT)
    session = requests.Session()
    if KUBE_AUTH_TOKEN:
        logger.debug("Using Auth Token: %s", KUBE_AUTH_TOKEN)
        session.headers.update({'Authorization': 'Bearer ' + KUBE_AUTH_TOKEN})
    response = session.get(KUBE_API_ROOT + resource, verify=False)
    return json.loads(response.text)