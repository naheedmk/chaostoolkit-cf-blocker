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

    hosts = {}

    with Popen('{} -e {} -d {} ssh {}'.format(bosh, cfg['bosh']['env'], cfg['bosh']['cf-dep'], cfg['bosh']['cfdot-dc']),
               shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=enc) as proc:
        stdout, _ = proc.communicate(input='cfdot actual-lrp-groups | grep --color=never {}\nexit\n'.format(guid), timeout=30)
        if proc.returncode:
            sys.exit("Failed retrieving LRP data from {}".format(cfg['bosh']['cfdot-dc']))

        stdout = stdout.splitlines()
        for line in stdout:
            try:
                instance = json.loads(line)['instance']
            except json.JSONDecodeError:
                continue

            if instance['state'] != 'RUNNING':
                continue

            host_ip = instance['address']
            cont_ip = instance['instance_address']
            assert hosts.get(host_ip) is None
            cont_ports = set()

            for p in instance['ports']:
                host_port = p['host_port']
                cont_port = p['container_port']

                if host_port in cfg['host-port-whitelist']:
                    continue
                if cont_port in cfg['container-port-whitelist']:
                    continue

                cont_ports.add(cont_port)
                print('Found application at {}:{} with container port {}'.format(host_ip, host_port, cont_port))

            hosts[host_ip] = (cont_ip, cont_ports)

        if not hosts:
            sys.exit("No hosts found!")

    diego_cells = {}
    for host_ip, (cont_ip, cont_ports) in hosts.items():
        cmd = "{} -e {} -d {} vms | grep -P '\s{}\s' | grep -Po '^diego-cell/[a-z0-9-]*'" \
            .format(bosh, cfg['bosh']['env'], cfg['bosh']['cf-dep'], host_ip.replace('.', '\.'))

        with Popen(cmd, shell=True, stdout=PIPE, stderr=DEVNULL, encoding=enc) as proc:
            if proc.returncode:
                print("Failed retrieving VM information from BOSH for {}.".format(host_ip),
                      file=sys.stderr)
                continue
            dc = proc.stdout.readline().rstrip('\r\n')

        assert diego_cells.get(dc) is None
        diego_cells[dc] = (host_ip, cont_ip, cont_ports)

    for dc, (host_ip, cont_ip, cont_ports) in diego_cells.items():
        print("Targeting {} at {} on {}:{}.".format(host_ip, dc, cont_ip, cont_ports))

    for dc, (host_ip, cont_ip, cont_ports) in diego_cells.items():
        with Popen('{} -e {} -d {} ssh {}'.format(bosh, cfg['bosh']['env'], cfg['bosh']['cf-dep'], dc),
                   shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=enc) as proc:

            for cont_port in cont_ports:
                proc.stdin.write('sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port))
            proc.stdin.write('exit\n')
            proc.stdin.close()

            if proc.returncode:
                sys.exit("Failed to block {}:{} on {}.".format(cont_ip, cont_port, dc))


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