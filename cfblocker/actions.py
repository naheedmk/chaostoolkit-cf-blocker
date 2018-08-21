from chaoslib.types import Configuration
from typing import Any, Dict

from cfblocker.app import App
from cfblocker.util import run_ctk as _run


def block_traffic(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Block all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(cfg)
        app.block(cfg)
        if cfg.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        return app

    return _run(f, "Blocking all traffic to {}...".format(appname))


def unblock_traffic(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Unblock all traffic to the application.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        if cfg.get('database'):
            # TODO: Implement reading from a DB what we last targeted
            assert False
        else:
            app = App(org, space, appname)
            app.find_hosts(cfg)

        app.unblock(cfg)
        return app

    return _run(f, "Unblocking all traffic to {}...".format(appname))


def block_services(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Block the application from reaching all its services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(cfg)
        app.find_services(cfg)
        if cfg.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        app.block_services(cfg)
        return app

    return _run(f, "Blocking traffic to all services bound to {}...".format(appname))


def unblock_services(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Unblock the application from reaching all its services.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        if cfg.get('database'):
            # TODO: Implement reading from a DB what we targeted
            assert False
        else:
            app.find_hosts(cfg)
            app.find_services(cfg)
        app.unblock_services(cfg)
        return app

    return _run(f, "Unblocking traffic to all services bound to {}...".format(appname))


def block_service(org: str, space: str, appname: str, service_name: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Block the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(cfg)
        app.find_services(cfg)
        if cfg.get('database'):
            # TODO: Implement writing to a DB what we targeted
            assert False
        app.block_services(cfg, service_name)
        return app

    return _run(f, "Blocking access to {}...".format(service_name))


def unblock_service(org: str, space: str, appname: str, service_name: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Unblock the application from reaching a specific service.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param service_name: String; Name of the Cloud Foundry service to block.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        if cfg.get('database'):
            # TODO: Implement reading from a DB what we targeted
            assert False
        else:
            app.find_hosts(cfg)
            app.find_services(cfg)
        app.unblock_services(cfg, service_name)
        return app

    return _run(f, "Unblocking access to {}...".format(service_name))
