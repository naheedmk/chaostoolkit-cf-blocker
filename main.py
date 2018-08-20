import sys
import yaml
import json

from cfblocker.app import App
from cfblocker.util import cf_target

# Record of past hosts and services we have targeted which allows us to undo our actions exactly as we had done them.
# This prevents lingering rules from existing if CF moves an app between the time it was blocked and unblocked.
TARGETED_LAST = 'targeted.json'

# Record of what hosts and services were discovered on the last run. This is for reference only.
DISCOVERY_FILE = 'discovered.json'


def save_targeted(filename, app):
    """
    Save the targeted hosts to a JSON file. This allows for the same hosts that were blocked to be unblocked even if
    cloud foundry moves application instances to a different container or diego-cell.
    :param filename: String; Name of the file to save to.
    :param app: App; The application to save.
    """
    try:
        with open(filename, 'r') as file:
            j = json.load(file)
    except FileNotFoundError:
        j = {}

    app.serialize(obj=j)

    with open(filename, 'w') as file:
        json.dump(j, file, indent=2)


def load_targeted(filename, org, space, name):
    """
    Load a json file of known hosts and services. This allows for the same hosts that were blocked to be unblocked even
    if cloud foundry moves application instances to a different container or diego-cell. This will remove the entries
    for the specific app from the json file.
    :param filename: String; Name of the file to load from.
    :param org: String; Name of the organization the app is in within cloud foundry.
    :param space: String; Name of the space the app is in within cloud foundry.
    :param name: String; Name of the app within cloud foundry.
    :return: App; The application with the org, space, and name or None if it was not present.
    """
    with open(filename, 'r') as file:
        j = json.load(file)

    app = App.deserialize(j, org, space, name, readonly=False)

    with open(filename, 'w') as file:
        # dump the json missing the hosts that we are unblocking
        json.dump(j, file, indent=2, sort_keys=True)

    return app


def main():
    """
    The function which should be called if this is being used as an executable and not being imported as a library.
    It should also give an idea of what functions need to be called an in what order to block or unblock an application.
    """
    args = sys.argv[1:]
    if len(args) not in [4, 5]:
        print("Usage: cf_block_app <block:unblock> <org> <space> <app> [<config_path>]")
        exit(1)

    config_path = (args[4:5] or ['config.yml'])[0]
    with open(config_path, 'r') as file:
        cfg = yaml.load(file)

    assert args[0] in ['block', 'unblock', 'block_services', 'discover']
    action = args[0]

    org, space, appname = args[1], args[2], args[3]

    if cf_target(org, space, cfg):
        sys.exit("Failed to target {} and {}. Make sure you are logged in and the names are correct!"
                 .format(org, space))

    if action == 'block':
        app = App(org, space, appname)
        app.find_hosts(cfg)
        save_targeted(TARGETED_LAST, app)
        app.block(cfg)
    elif action == 'unblock':
        app = load_targeted(TARGETED_LAST, org, space, appname)
        app.unblock(cfg)
        app.unblock_services(cfg)
    elif action == 'block_services':
        app = App(org, space, appname)
        app.find_hosts(cfg)
        app.find_services(cfg)
        save_targeted(TARGETED_LAST, app)
        app.block_services(cfg)
    elif action == 'discover':
        app = App(org, space, appname)
        app.find_hosts(cfg)
        app.find_services(cfg)
        # TODO: just print this?
        save_targeted(DISCOVERY_FILE, app)
    else:
        sys.exit("UNKNOWN OPTION!")

    print("\n=======\n Done!\n=======")


if __name__ == '__main__':
    main()
