import json
import sys
import yaml
from subprocess import call, Popen, PIPE, DEVNULL

DEFAULT_ENCODING = 'UTF-8'


def main(org, space, appname, cfg):
    enc = DEFAULT_ENCODING
    cf = cfg['cf']['cmd'] or 'cf'
    bosh = cfg['bosh']['cmd'] or 'bosh2'

    if call([cf, 'target', '-o', org, '-s', space]):
        sys.exit("Failed to target {} and {}. Make sure you are logged in and the names are correct!"
                 .format(org, space))

    with Popen([cf, 'app', appname, '--guid'], stdout=PIPE, stderr=DEVNULL, encoding=enc) as proc:
        guid = proc.stdout.readline().rstrip('\r\n')
        if proc.returncode:
            sys.exit("Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(appname))

    hosts = set()

    with Popen([cf, 'curl', '/v2/apps/{}/stats'.format(guid)], stdout=PIPE, stderr=DEVNULL) as proc:
        if proc.returncode:
            sys.exit("Failed retrieving the ip and port for {}.".format(appname))

        for _, app in json.load(proc.stdout):
            if app['stats']['name'] != appname:
                continue

            host_ip = app['stats']['host']
            host_port = app['stats']['port']
            print('Found host {}:{}'.format(host_ip, host_port))

            hosts.add(host_ip)

    diego_cells = set()
    for host_ip in hosts:
        cmd = "{} -e {} -d {} vms | grep {} | grep -Po '^diego-cell/[a-z0-9-]*'" \
            .format(bosh, cfg['bosh']['env'], cfg['bosh']['cf-dep'], host_ip)

        with Popen(cmd, shell=True, stdout=PIPE, stderr=DEVNULL, encoding=enc) as proc:
            if proc.returncode:
                print("Failed retrieving VM information from BOSH for {}.".format(host_ip),
                      file=sys.stderr)
                continue
            dc = proc.stdout.readline().rstrip('\r\n')

        diego_cells.add(dc)

    for dc in diego_cells:
        with Popen("{} -e {} -d {} ssh {} -c 'sudo cat /var/vcap/data/container-metadata/store.json'"
                              .format(bosh, cfg['bosh']['env'], cfg['bosh']['cf-dep'], dc),
                      shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=enc) as proc:

            if proc.returncode:
                sys.exit("Failed to retrieve container metadata from {}".format(dc))

            store = json.loads(
                proc.stdout
                    .readlines()[-2]  # get the second from last line, it is the actual output
                    .split(' | ')[1]  # remove the 'diego-cell/...: stdout | ' garbage
            )

        for _handle, app in store:
            if app['appid'] != guid:
                continue
            app_ip = app['ip']

            # TODO: does this work for multiple app instances? If so, how does it know which app to ssh into?
            with Popen("{} ssh {} -c 'echo $PORT'".format(cf, appname)) as proc:
                if proc.returncode:
                    sys.exit("Failed to get port for app on {} with container ip {}.".format(dc, app_ip))

                app_port = int(proc.stdout.read())

            with Popen("{} -e {} -d {} ssh {} -c 'iptables -I FORWARD 1 -d {} --dport {} -j DROP'"
                                  .format(bosh, cfg['bosh']['env'], cfg['bosh']['cf-dep'], dc, app_ip, app_port),
                          shell=True, stdout=DEVNULL, stderr=DEVNULL) as proc:

                if proc.returncode:
                    sys.exit("Failed to block {}:{} on {}.".format(app_ip, app_port, dc))


if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) not in [3, 4]:
        print("Usage: cf_block_app <org> <space> <app>, [<config_path>]")
        exit(1)

    config_path = args[3] if len(args) == 4 else 'config.yml'
    with open(config_path, 'r') as file:
        config = yaml.load(file)

    main(args[0], args[1], args[2], config)


# 75479234-b154-42f2-bd04-0c6d1abc83da