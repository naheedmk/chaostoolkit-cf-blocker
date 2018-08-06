import json
import sys
import yaml
from subprocess import call, Popen, PIPE, DEVNULL
from collections import namedtuple

DEFAULT_ENCODING = 'UTF-8'
ContainerInfo = namedtuple('Host', ['cont_ip', 'cont_ports'])
DiegoContainerInfo = namedtuple('DiegoCell', ['diego_ip', 'cont_ip', 'cont_ports'])


def cf_target(org, space, cfg):
    return call([cfg['cf']['cmd'], 'target', '-o', org, '-s', space])


def get_guid(appname, cfg):
    with Popen([cfg['cf']['cmd'], 'app', appname, '--guid'], stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
        guid = proc.stdout.readline().rstrip('\r\n')
        if proc.returncode:
            sys.exit("Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(appname))

    return guid


def get_container_hosts(guid, cfg):
    hosts = {}
    with Popen('{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], cfg['bosh']['cfdot-dc']),
               shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
        stdout, _ = proc.communicate(input='cfdot actual-lrp-groups | grep --color=never {}\nexit\n'.format(guid),
                                     timeout=30)
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

            hosts[host_ip] = ContainerInfo(cont_ip, cont_ports)

    return hosts


def get_diego_vm_name(diego_ip, cfg):
    cmd = "{} -e {} -d {} vms | grep -P '\s{}\s' | grep -Po '^diego-cell/[a-z0-9-]*'" \
        .format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], diego_ip.replace('.', '\.'))

    with Popen(cmd, shell=True, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
        if proc.returncode:
            print("Failed retrieving VM information from BOSH for {}.".format(diego_ip),
                  file=sys.stderr)
            return None
        diego_vm = proc.stdout.readline().rstrip('\r\n')

    return diego_vm


def block_app(diego_vm, dci, cfg):
    with Popen('{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], diego_vm),
               shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:

        for cont_port in dci.cont_ports:
            proc.stdin.write(
                'sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP\n'.format(dci.cont_ip, cont_port))
        proc.stdin.write('exit\n')
        proc.stdin.close()

        return proc.returncode


def unblock_app(diego_vm, dci, cfg):
    with Popen('{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], diego_vm),
               shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
        for cont_port in dci.cont_ports:
            proc.stdin.write(
                'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP\n'.format(dci.cont_ip, cont_port))
        proc.stdin.write('exit\n')
        proc.stdin.close()

        return proc.returncode


def main(org, space, appname, block, cfg):
    if cf_target(org, space, cfg):
        sys.exit("Failed to target {} and {}. Make sure you are logged in and the names are correct!"
                 .format(org, space))

    guid = get_guid(appname, cfg)

    hosts = get_container_hosts(guid, cfg)
    if not hosts:
        sys.exit("No hosts found!")

    diego_cells = {}
    for host_ip, ci in hosts.items():
        diego_vm = get_diego_vm_name(host_ip, cfg)

        if diego_vm is None:
            continue
        assert diego_cells.get(diego_vm) is None

        diego_cells[diego_vm] = DiegoContainerInfo(host_ip, ci.cont_ip, ci.cont_ports)

    for diego_vm, dci in diego_cells.items():
        print("Targeting {} at {} on {}:{}.".format(dci.diego_ip, diego_vm, dci.cont_ip, dci.cont_ports))

    for diego_vm, dci in diego_cells.items():
        if block:
            if block_app(diego_vm, dci, cfg):
                sys.exit("Failed to block {}:{} on {}.".format(dci.cont_ip, dci.cont_ports, diego_vm))
        else:
            if unblock_app(diego_vm, dci, cfg):
                print("WARNING: Failed to unblock {}:{} on {}.".format(dci.cont_ip, dci.cont_ports, diego_vm))

    print("Done!")


if __name__ == '__main__':
    args = sys.argv[1:]
    if len(args) not in [4, 5]:
        print("Usage: cf_block_app <block:unblock> <org> <space> <app> [<config_path>]")
        exit(1)

    config_path = args[4] if len(args) == 5 else 'config.yml'
    with open(config_path, 'r') as file:
        config = yaml.load(file)

    assert args[0] in ['block', 'unblock']

    main(args[1], args[2], args[3], args[0] == 'block', config)


# 75479234-b154-42f2-bd04-0c6d1abc83da