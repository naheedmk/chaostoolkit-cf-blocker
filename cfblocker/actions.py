from chaoslib.types import Configuration
from typing import Any, Dict

from cfblocker.app import App
from cfblocker.util import run_ctk as _run


def block_traffic(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Block all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(configuration)
        app.block(configuration)
        if configuration.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        return app

    return _run(f, "Blocking all traffic to {}...".format(appname))


def unblock_traffic(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Unblock all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        if configuration.get('database'):
            # TODO: Implement reading from a DB what we last targeted
            assert False
        else:
            app = App(org, space, appname)
            app.find_hosts(configuration)

        app.unblock(configuration)
        return app

    return _run(f, "Unblocking all traffic to {}...".format(appname))


def block_services(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Block the application from reaching all its services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(configuration)
        app.find_services(configuration)
        if configuration.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        app.block_services(configuration)
        return app

    return _run(f, "Blocking traffic to all services bound to {}...".format(appname))


def unblock_services(org: str, space: str, appname: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Unblock the application from reaching all its services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        if configuration.get('database'):
            # TODO: Implement reading from a DB what we targeted
            assert False
        else:
            app.find_hosts(configuration)
            app.find_services(configuration)
        app.unblock_services(configuration)
        return app

    return _run(f, "Unblocking traffic to all services bound to {}...".format(appname))


def block_service(org: str, space: str, appname: str, service_name: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Block the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(configuration)
        app.find_services(configuration)
        if configuration.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        app.block_services(configuration, service_name)
        return app

    return _run(f, "Blocking access to {}...".format(service_name))


def unblock_service(org: str, space: str, appname: str, service_name: str, configuration: Configuration) -> Dict[str, Any]:
    """
    Unblock the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param configuration: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        if configuration.get('database'):
            # TODO: Implement reading from a DB what we targeted
            assert False
        else:
            app.find_hosts(configuration)
            app.find_services(configuration)
        app.unblock_services(configuration, service_name)
        return app

    return _run(f, "Unblocking access to {}...".format(service_name))
