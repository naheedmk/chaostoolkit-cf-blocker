import json
import sys
import yaml
from subprocess import call, Popen, PIPE, DEVNULL

DEFAULT_ENCODING = 'UTF-8'
TARGETED_HOSTS = 'targeted.json'


class DiegoHost:
    """
    This represents a Diego-cell running in a BOSH environment. It contains the ip and name of the Diego-cell, and it
    stores all the containers hosting the app that are within thee specific Diego-cell. The container hosts are listed
    as a mapping from the container IP to the application ports, e.g. {"10.5.34.2": set([80, 8080]), ...}
    """

    def __init__(self, ip):
        self.ip = ip
        self.vm = None
        self.containers = {}

    def __iter__(self):
        return self.containers.__iter__()

    def __contains__(self, item):
        return self.containers.__contains__(item)

    def __len__(self):
        return len(self.containers)

    def __hash__(self):
        return hash(self.ip)

    def __getitem__(self, cont_ip):
        return self.containers[cont_ip]

    def __setitem__(self, key, value):
        self.containers[key] = value

    def __delitem__(self, key):
        return self.containers.__delitem__(key)

    def add_instance(self, cont_ip, cont_ports):
        """
        Add a new container or new container ports. It will automatically merge ports instead of replacing the existing
        entry if there is already information for the specified container.

        :param cont_ip: IP Address of the container hosted on this diego-cell.
        :param cont_ports: The set of ports which the application is bound to on the container.
        :return:
        """
        ports = self.containers.get(cont_ip, set())
        ports |= cont_ports
        self[cont_ip] = ports

    def find_diego_vm_name(self, cfg):
        cmd = "{} -e {} -d {} vms | grep -P '\s{}\s' | grep -Po '^diego-cell/[a-z0-9-]*'" \
            .format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.ip.replace('.', '\.'))

        with Popen(cmd, shell=True, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            if proc.returncode:
                print("Failed retrieving VM information from BOSH for {}.".format(self.ip),
                      file=sys.stderr)
                return None
            self.vm = proc.stdout.readline().rstrip('\r\n')

        return self.vm

    def block(self, cfg):
        with Popen(
                '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm),
                shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:

            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    print("Targeting {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    proc.stdin.write(
                        'sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port))

            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def unblock(self, cfg):
        with Popen(
                '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm),
                shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    print("Unblocking {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    proc.stdin.write(
                        'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port))
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode


class HostedApp:
    """
    Information about an application and all of the locations it is hosted.
    """

    def __init__(self, org, space, appname):
        self.org = org
        self.space = space
        self.appname = appname
        self.guid = None
        self.diego_hosts = {}

    def __iter__(self):
        return self.diego_hosts.__iter__()

    def __contains__(self, item):
        return self.diego_hosts.__contains__(item)

    def __len__(self):
        return len(self.diego_hosts)

    def __hash__(self):
        return hash(self.id())

    def __getitem__(self, item):
        return self.diego_hosts[item]

    def __setitem__(self, key, value):
        self.diego_hosts[key] = value

    def __delitem__(self, key):
        return self.diego_hosts.__delitem__(key)

    def id(self):
        return '{}_{}_{}'.format(self.org, self.space, self.appname)

    def add_diego_cell(self, dc):
        """
        Adds a diego cell as a host of this app. It will merge any of the internal container information if the new
        diego-cell is already present.

        :param dc: The new Diego-cell to add/merge
        """
        if dc.ip in self.diego_hosts:
            d_host = self.diego_hosts[dc.ip]
            for cont_ip, cont_ports in dc.items():
                d_host.add_instance(cont_ip, cont_ports)
        else:
            self.diego_hosts[dc.ip] = dc

    def find_hosts(self, cfg):
        self._find_guid(cfg)
        self._find_container_hosts(cfg)

        for dc in self.diego_hosts.values():
            if dc.find_diego_vm_name(cfg) is None:
                continue

        return self.diego_hosts

    def block(self, cfg):
        for dc in self.diego_hosts.values():
            ret = dc.block(cfg)

            if ret:
                print("WARNING: could not block all hosts; failed on {}.".format(dc.vm), file=sys.stderr)
                return ret

    def unblock(self, cfg):
        for dc in self.diego_hosts.values():
            ret = dc.unblock(cfg)

            if ret:
                print("WARNING: could not unblock all hosts; failed on {}.".format(dc.vm), file=sys.stderr)
                return ret

    def save_hosts(self, filename):
        try:
            with open(filename, 'r') as file:
                j = json.load(file)
        except FileNotFoundError:
            j = {}

        with open(filename, 'w') as file:
            if self.id() in j:
                japp = j[self.id()]
                assert self._validate_japp(japp)
            else:
                japp = {
                    'appname': self.appname,
                    'org': self.org,
                    'space': self.space,
                    'diego_hosts': {}
                }

            for dc in self.diego_hosts.values():
                if dc.ip in japp['diego_hosts']:
                    jdc = japp['diego_hosts'][dc.ip]
                    assert jdc['vm'] == dc.vm
                    assert jdc['ip'] == dc.ip
                else:
                    jdc = {'ip': dc.ip, 'vm': dc.vm, 'containers': {}}

                for cont_ip, cont_ports in dc.containers.items():
                    jports = set(jdc.get(cont_ip, []))
                    jdc['containers'][cont_ip] = list(jports | cont_ports)

                japp['diego_hosts'][dc.ip] = jdc
            j[self.id()] = japp

            json.dump(j, file, indent=2, sort_keys=True)

    def load_hosts(self, filename):
        with open(filename, 'r') as file:
            j = json.load(file)

        japp = j.pop(self.id(), None)
        if japp is None:
            return False

        assert self._validate_japp(japp)

        for diego_ip, jdc in japp['diego_hosts'].items():
            assert self._validate_jdc(jdc)
            dc = DiegoHost(diego_ip)
            dc.vm = jdc['vm']

            for cont_ip, cont_ports in jdc['containers'].items():
                dc.add_instance(cont_ip, set(cont_ports))

            self.add_diego_cell(dc)

        with open(filename, 'w') as file:
            # dump the json missing the hosts that we are unblocking
            json.dump(j, file, indent=2, sort_keys=True)

    def _validate_japp(self, japp):
        return \
            japp['appname'] == self.appname and \
            japp['org'] == self.org and \
            japp['space'] == self.space

    def _validate_jdc(self, jdc):
        dc = self.diego_hosts.get(jdc['ip'], None)
        # if we do not know about this diego-cell, we are good
        # if we have not yet checked the vm, assume it is good
        # otherwise, make sure they match
        return \
            dc is None or \
            dc.vm is None or \
            jdc['vm'] == dc.vm

    def _find_guid(self, cfg):
        with Popen([cfg['cf']['cmd'], 'app', self.appname, '--guid'], stdout=PIPE, stderr=DEVNULL,
                   encoding=DEFAULT_ENCODING) as proc:
            guid = proc.stdout.readline().rstrip('\r\n')
            if proc.returncode:
                sys.exit(
                    "Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(self.appname))

        self.guid = guid
        return guid

    def _find_container_hosts(self, cfg):
        with Popen('{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'],
                                                  cfg['bosh']['cfdot-dc']),
                   shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            stdout, _ = proc.communicate(input='cfdot actual-lrp-groups | grep --color=never {}\nexit\n'.format(self.guid),
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

                host = DiegoHost(host_ip)
                host.add_instance(cont_ip, cont_ports)
                self.add_diego_cell(host)

        return self.diego_hosts


def cf_target(org, space, cfg):
    return call([cfg['cf']['cmd'], 'target', '-o', org, '-s', space])


def main():
    args = sys.argv[1:]
    if len(args) not in [4, 5]:
        print("Usage: cf_block_app <block:unblock> <org> <space> <app> [<config_path>]")
        exit(1)

    config_path = (args[4:5] or ['config.yml'])[0]
    with open(config_path, 'r') as file:
        cfg = yaml.load(file)

    assert args[0] in ['block', 'unblock']
    block = args[0] == 'block'

    app = HostedApp(args[1], args[2], args[3])

    if cf_target(app.org, app.space, cfg):
        sys.exit("Failed to target {} and {}. Make sure you are logged in and the names are correct!"
                 .format(app.org, app.space))

    if block:
        app.find_hosts(cfg)
        app.save_hosts(TARGETED_HOSTS)
        app.block(cfg)
    else:
        app.load_hosts(TARGETED_HOSTS)
        app.unblock(cfg)

    print("Done!")


if __name__ == '__main__':
    main()