import json
import sys
import yaml
from subprocess import call, Popen, PIPE, DEVNULL
from collections import namedtuple

DEFAULT_ENCODING = 'UTF-8'

# TODO: define class Host to solidify the type
# {"diego_ip": {"c1_ip": {p1, p2}, "c2_ip": {p1}}


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

            host = hosts.get(host_ip) or {}
            assert host.get(cont_ip) is None
            host[cont_ip] = cont_ports
            hosts[host_ip] = host

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


def block_app(diego_vm, host, cfg):
    with Popen('{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], diego_vm),
               shell=True, stdin=PIPE, encoding=DEFAULT_ENCODING) as proc:

        for cont_ip, cont_ports in host.items():
            for cont_port in cont_ports:
                proc.stdin.write(
                    'sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port))

        proc.stdin.write('exit\n')
        proc.stdin.close()

        return proc.returncode


def unblock_app(diego_vm, host, cfg):
    with Popen('{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], diego_vm),
               shell=True, stdin=PIPE, encoding=DEFAULT_ENCODING) as proc:
        for cont_ip, cont_ports in host.items():
            for cont_port in cont_ports:
                proc.stdin.write(
                    'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port))
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
    for diego_ip, host in hosts.items():
        diego_vm = get_diego_vm_name(diego_ip, cfg)

        if diego_vm is None:
            continue
        assert diego_cells.get(diego_vm) is None

        diego_cells[diego_vm] = (diego_ip, host)

    for diego_vm, (diego_ip, host) in diego_cells.items():
        for cont_ip, cont_ports in host.items():
            print("Targeting {} at {} on {}:{}.".format(diego_ip, diego_vm, cont_ip, cont_ports))

    for diego_vm, (_, host) in diego_cells.items():
        if block:
            if block_app(diego_vm, host, cfg):
                sys.exit("Failed to block one or more of {} on {}.".format(host, diego_vm))
        else:
            if unblock_app(diego_vm, host, cfg):
                print("WARNING: Failed to unblock one or more of {} on {}.".format(host, diego_vm))

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
