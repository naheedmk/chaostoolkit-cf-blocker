from chaoslib.types import Configuration
from typing import Any, Dict

from cfblocker.app import App
from cfblocker.util import run_ctk as _run


def find_hosts(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Find all hosts of this application in Cloud Foundry.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_hosts(cfg)
        return app

    return _run(f, "Finding all application hosts...")


def find_services(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Find all services of this application in Cloud Foundry.
    :param org: String; Cloud Foundry organization containing the application.
    :param space: String; Cloud Foundry space containing the application.
    :param appname: String; Application in Cloud Foundry which is to be targeted.
    :param cfg: Configuration; Configuration details, see `README.md`.
    :return: A JSON Object representing the application which was targeted.
    """
    def f():
        app = App(org, space, appname)
        app.find_services(cfg)
        return app

    return _run(f, "Finding all application services...")


def find_all(org: str, space: str, appname: str, cfg: Configuration) -> Dict[str, Any]:
    """
    Find all hosts and all services for this application in Cloud Foundry.
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
        return app

    return _run(f, "Finding all application hosts and services...")
