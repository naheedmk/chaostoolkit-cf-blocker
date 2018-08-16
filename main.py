import sys
import yaml

from cfblocker.app import HostedApp
from cfblocker.util import cf_target

# Record of past hosts and services we have targeted which allows us to undo our actions exactly as we had done them.
# This prevents lingering rules from existing if CF moves an app between the time it was blocked and unblocked.
TARGETED_LAST = 'targeted.json'

# Record of what hosts and services were discovered on the last run. This is for reference only.
DISCOVERY_FILE = 'discovered.json'


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

    app = HostedApp(args[1], args[2], args[3])

    if cf_target(app.org, app.space, cfg):
        sys.exit("Failed to target {} and {}. Make sure you are logged in and the names are correct!"
                 .format(app.org, app.space))

    if action == 'block':
        app.find_hosts(cfg)
        app.save(TARGETED_LAST)
        app.block(cfg)
    elif action == 'unblock':
        app.load(TARGETED_LAST)
        app.unblock(cfg)
        app.unblock_services(cfg)
    elif action == 'block_services':
        app.find_hosts(cfg)
        app.find_services(cfg)
        app.save(TARGETED_LAST)
        app.block_services(cfg)
    elif action == 'discover':
        app.find_hosts(cfg)
        app.find_services(cfg)
        # TODO: just print this?
        app.save(DISCOVERY_FILE, overwrite=False)
    else:
        sys.exit("UNKNOWN OPTION!")

    print("\n=======\n Done!\n=======")


if __name__ == '__main__':
    main()
