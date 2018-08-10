import json
import sys
import yaml
from subprocess import call, Popen, PIPE, DEVNULL

# Default encoding we assume all pipes should use
DEFAULT_ENCODING = 'UTF-8'

# Record of past hosts we have targeted which allows us to undo our actions exactly as we had done them. This prevents
# lingering rules from existing if CF moves an app between the time it was blocked and unblocked.
TARGETED_HOSTS = 'targeted.json'

# Number of times we should remove the iptables rule we added to block an app. This should be greater than one in case
# you accident run this script to block it more than once before unblocking it.
TIMES_TO_REMOVE = 6


class DiegoHost:
    """
    This represents a Diego-cell running in a BOSH environment. It contains the ip and name of the Diego-cell, and it
    stores all the containers hosting the app that are within thee specific Diego-cell. The container hosts are listed
    as a mapping from the container IP to the application ports, e.g. {"10.5.34.2": set([80, 8080]), ...}
    """

    def __init__(self, ip):
        """
        Initialize a new Diego-cell representation.

        :param ip: IP of this diego-cell.
        """
        self.ip = ip
        self.vm = None
        self.containers = {}

    def __iter__(self):
        """
        Iterate over the containers in this Diego-cell.
        :return: An iterator over the containers in this Diego-cell.
        """
        return self.containers.__iter__()

    def __contains__(self, item):
        """
        Check if this Diego-cell contains a given container.
        :param item: The container IP.
        :return: Whether the containers is in this Diego-cell.
        """
        return self.containers.__contains__(item)

    def __len__(self):
        """
        Find how many containers are within this Diego-cell.
        :return: The number of containers within this Diego-cell.
        """
        return len(self.containers)

    def __hash__(self):
        """
        A unique identifier for this Diego-cell based on its IP.
        :return: A hash of this Diego-cell's IP.
        """
        return hash(self.ip)

    def __getitem__(self, cont_ip):
        """
        Get a container within this Diego-cell by its IP.
        :param cont_ip: IP of the container in question.
        :return: The set of ports on that container the application is attached to.
        """
        return self.containers[cont_ip]

    def __setitem__(self, key, value):
        """
        Set the ports the application is attached to for the given container.
        :param key: The container IP for which the ports are relevant.
        :param value: Set of ports the application is bound to.
        """
        self.containers[key] = value

    def __delitem__(self, key):
        """
        Remove a container and its set of ports.
        :param key: The container IP.
        """
        return self.containers.__delitem__(key)

    def add_instance(self, cont_ip, cont_ports):
        """
        Add a new container or new container ports. It will automatically merge ports instead of replacing the existing
        entry if there is already information for the specified container.
        :param cont_ip: IP Address of the container hosted on this diego-cell.
        :param cont_ports: The set of ports which the application is bound to on the container.
        """
        ports = self.containers.get(cont_ip, set())
        ports |= cont_ports
        self[cont_ip] = ports

    def find_diego_vm_name(self, cfg):
        """
        Query bosh for the VM name of this diego cell given its IP address. This will simply return the current VM name
        if it has already been found.
        :param cfg: Configuration information about the environment.
        :return: The VM name.
        """
        if self.vm:
            return self.vm

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
        """
        Block the application on this diego-cell. It will create new iptables rules on the diego-cell to block all
        traffic forwarded to the application.
        :param cfg: Configuration information about the environment.
        :return: The returncode of the bosh ssh program.
        """
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
        """
        Unblock the application on this diego-cell. It will delete the iptables rule on this diego-cell based on its
        description. (i.e. it does not blindly delete the first item which allows multiple different apps to be blocked
        on the same diego-cell.)
        :param cfg: Configuration information about the environment.
        :return: The returncode of the bosh ssh program.
        """
        with Popen(
                '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm),
                shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    print("Unblocking {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    for _ in range(TIMES_TO_REMOVE):
                        proc.stdin.write('sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP\n'\
                                         .format(cont_ip, cont_port))
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode


class HostedApp:
    """
    Information about an application and all of the locations it is hosted.
    """

    def __init__(self, org, space, appname):
        """
        Initialize a new hosted app object.
        :param org: The cloud foundry organization the application is hosted in.
        :param space: The cloud foundry organization space the application is hosted in.
        :param appname: The name of the application deployment within cloud foundry.
        """

        self.org = org
        self.space = space
        self.appname = appname
        self.guid = None
        self.diego_hosts = {}

    def __iter__(self):
        """
        Iterate over each of the diego-cells the application is hosted on.
        :return: An iterator over the diego-cells the application is hosted on.
        """
        return self.diego_hosts.__iter__()

    def __contains__(self, item):
        """
        Check if a given diego-cell is listed as a host of this application.
        :param item: The IP of the diego-cell.
        :return: Whether the diego-cell is a known of this application.
        """
        return self.diego_hosts.__contains__(item)

    def __len__(self):
        """
        Find how many diego-cells host this application.
        :return: The number of diego-cells which host this application.
        """
        return len(self.diego_hosts)

    def __hash__(self):
        """
        Calculate a unique identifier for this application based on its organization, space, and application name.
        :return: A unique identifier for this application.
        """
        return hash(self.id())

    def __getitem__(self, item):
        """
        Retrieve information about a diego-cell which hosts this application.
        :param item: The IP address of the diego-cell in question.
        :return: The diego-cell with the given IP address.
        """
        return self.diego_hosts[item]

    def __setitem__(self, key, value):
        """
        Specify a diego-cell host of this application.
        :param key: The IP address of the diego-cell.
        :param value: Thew diego-cell information.
        """
        self.diego_hosts[key] = value

    def __delitem__(self, key):
        """
        Remove a diego-cell as a known host of this application.
        :param key: The IP address of the diego-cell.
        """
        return self.diego_hosts.__delitem__(key)

    def id(self):
        """
        Create a unique descriptor for this application. It will take the form 'org_space_appname'.
        :return: A unique descriptor for this application.
        """
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
        """
        Find all diego-cells and respective containers which host this application. This will first find the GUID of the
        CF application and then find what diego-cells and containers are running the application. It will update the
        internal hosts lists as well as return the information.
        :param cfg: Configuration information about the environment.
        :return: The list of diego-cells which host this application.
        """
        self._find_guid(cfg)
        self._find_container_hosts(cfg)

        for dc in self.diego_hosts.values():
            dc.find_diego_vm_name(cfg)

        return self.diego_hosts

    def block(self, cfg):
        """
        Block this application on all its known hosts.
        :param cfg: Configuration information about the environment.
        :return: A returncode if any of the bosh ssh instances does not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.block(cfg)

            if ret:
                print("WARNING: could not block all hosts; failed on {}.".format(dc.vm), file=sys.stderr)
                return ret

        return 0

    def unblock(self, cfg):
        """
        Unblock this application on all its known hosts. This will actually run the unblock commands multiple times, as
        defined by `TIMES_TO_REMOVE` to prevent issues if an application was blocked multiple times.
        :param cfg: Configuration information about the environment.
        :return: A returncode if any of the bosh ssh instances does not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.unblock(cfg)

            if ret:
                print("WARNING: could not unblock all hosts; failed on {}.".format(dc.vm), file=sys.stderr)
                return ret

        return 0

    def save_hosts(self, filename):
        """
        Save all known hosts to a json file. This allows for the same hosts that were blocked to be unblocked even if
        cloud foundry moves application instances to a different container or diego-cell.
        :param filename: The name of the file to save the json object to.
        """
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

    def load_hosts(self, filename, remove=True):
        """
        Load a json file of known hosts. This allows for the same hosts that were blocked to be unblocked even if cloud
        foundry moves application instances to a different container or diego-cell. This will remove the entries for the
        specific app from the json file if `remove` is `True`.
        :param filename: The name of the json file to load information from.
        :param remove: Whether we should remove the entries this specific app or leave the file as it was.
        """
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

        if remove:
            with open(filename, 'w') as file:
                # dump the json missing the hosts that we are unblocking
                json.dump(j, file, indent=2, sort_keys=True)

    def _validate_japp(self, japp):
        """
        Quick way to verify a dictionary representation of an app is valid. This is used to validate json information.
        :param japp: Dictionary object to validate.
        :return: Whether it is a valid application representation.
        """
        return \
            japp['appname'] == self.appname and \
            japp['org'] == self.org and \
            japp['space'] == self.space

    def _validate_jdc(self, jdc):
        """
        Quick way to verify a dictionary representation of a diego-host is valid. This is used to validate json
        information.
        :param jdc: Dictionary ojbect to validate.
        :return: Whether it is a valid application representation.
        """
        dc = self.diego_hosts.get(jdc['ip'], None)
        # if we do not know about this diego-cell, we are good
        # if we have not yet checked the vm, assume it is good
        # otherwise, make sure they match
        return \
            dc is None or \
            dc.vm is None or \
            jdc['vm'] == dc.vm

    def _find_guid(self, cfg):
        """
        Find the GUID of an application using cloud foundry's CLI interface. The GUID acts as a unique identifier for
        the application which we can then use to find what containers are running it.
        :param cfg: Configuration information about the environment.
        :return: The application GUID.
        """
        with Popen([cfg['cf']['cmd'], 'app', self.appname, '--guid'], stdout=PIPE, stderr=DEVNULL,
                   encoding=DEFAULT_ENCODING) as proc:
            guid = proc.stdout.readline().rstrip('\r\n')
            if proc.returncode:
                sys.exit(
                    "Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(self.appname))

        self.guid = guid
        return guid

    def _find_container_hosts(self, cfg):
        """
        Find the containers which host this application by using cfdot.
        :param cfg: Configuration information about the environment.
        :return: The diego-cells which host this app and their associated sub-containers.
        """
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
    """
    Target a specific organization and space using the cloud foundry CLI. This should be run before anything which calls
    out to cloud foundry. This will fail if cloud foundry is not logged in.
    :param org: The organization to target.
    :param space: The space within the organization to target.
    :param cfg: Configuration information about the environment.
    :return: The returncode of the cloud foundry CLI.
    """
    return call([cfg['cf']['cmd'], 'target', '-o', org, '-s', space])


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