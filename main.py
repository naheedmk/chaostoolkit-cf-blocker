import json
import sys
import yaml
import re
from socket import gethostbyname as dnslookup
from subprocess import call, Popen, PIPE, DEVNULL

# Default encoding we assume all pipes should use
DEFAULT_ENCODING = 'UTF-8'

# Record of past hosts and services we have targeted which allows us to undo our actions exactly as we had done them.
# This prevents lingering rules from existing if CF moves an app between the time it was blocked and unblocked.
TARGETED_LAST = 'targeted.json'

# Record of what hosts and services were discovered on the last run. This is for reference only.
DISCOVERY_FILE = 'discovered.json'

# Number of times we should remove the iptables rule we added to block an app. This should be greater than one in case
# you accident run this script to block it more than once before unblocking it.
TIMES_TO_REMOVE = 6


class Service:
    @staticmethod
    def from_service_info(service_type, service_config):
        """
        Given a service configuration object and the name of the service, extract the hosts and username/password
        (if relevant).
        :param service_type: Name of the service the configuration is for, e.g. are 'p-mysql' or 'p-config-server'.
        :param service_config: Configuration object from VCAP_SERVICES for the provided service. Note, it is for one instance.
        :return: TODO: determine what exactly we want to return.
        """
        type = service_type
        name = service_config['name']
        user = None
        pswd = None
        hosts = set()

        credentials = service_config.get('credentials', None)

        if type == 'p-config-server':
            user = credentials['client_id']
            pswd = credentials['client_secret']
            match = re.match(r'https://([a-z0-9_.-]+):?(\d+)?', credentials['uri'])
            ip = dnslookup(match[1])  # from my testing, the diego-cells *should* find the same values
            port = match[2] or '443'
            hosts.add((ip, port))
        elif type == 'T-Logger':
            match = re.match(r'syslog://([a-z0-9_.-]+):(\d+)', credentials['syslog_drain_url'])
            ip = dnslookup(match[1])
            hosts.add((ip, match[2]))
        elif type == 'p-mysql':
            user = credentials['username']
            pswd = credentials['password']
            hosts.add((credentials['hostname'], credentials['port']))
        elif type == 'p-rabbitmq':
            user = credentials['username']
            pswd = credentials['password']
            for pconfig in credentials['protocols'].values():
                port = pconfig['port']
                for host in pconfig['hosts']:
                    hosts.add((host, port))
        else:
            print("Unrecognized service '{}'".format(type), file=sys.stderr)
            return None

        return Service(type, name, user, pswd, hosts)

    def __init__(self, type, name, user, pswd, hosts):
        """
        :param type: String; type of service; e.g. 'p-mysql'.
        :param name: String; name of this service instance (this is the name given when creating the service).
        :param user: String; username credential for this service.
        :param pswd: String; password credential for this service.
        :param hosts: Set((String, String)); Set of (IP, Port) tuples for where this service is hosted.
        """
        self.type = type
        self.name = name
        self.user = user
        self.pswd = pswd
        self.hosts = hosts

    def __repr__(self):
        return 'Service({}, {}, {}, {}, {})'.format(self.type, self.name, self.user, self.pswd, self.hosts)

    def id(self):
        """
        Generate a unique identifier for this service based on its name and type.
        :return: A unique identifier for this service.
        """
        return '{}:{}'.format(self.type, self.name)


class DiegoHost:
    """
    This represents a Diego-cell running in a BOSH environment. It contains the ip and name of the Diego-cell, and it
    stores all the containers hosting the app that are within thee specific Diego-cell. The container hosts are listed
    as a mapping from the container IP to the application ports, e.g. {"10.5.34.2": set([80, 8080]), ...}
    """

    def __init__(self, ip):
        """
        Initialize a new Diego-cell representation.

        :param ip: String; IP of this diego-cell.
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

        cmd = "{} -e {} -d {} vms | grep -P '\s{}\s' | grep -Po '^diego.cell/[a-z0-9-]*'" \
            .format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.ip.replace('.', '\.'))

        print('$ ' + cmd)
        with Popen(cmd, shell=True, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            if proc.returncode:
                print("Failed retrieving VM information from BOSH for {}.".format(self.ip),
                      file=sys.stderr)
                return None
            self.vm = proc.stdout.readline().rstrip('\r\n')
            print(self.vm)

        return self.vm

    def block(self, cfg):
        """
        Block the application on this diego-cell. It will create new iptables rules on the diego-cell to block all
        traffic forwarded to the application.
        :param cfg: Configuration information about the environment.
        :return: The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        print('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    print("Targeting {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    cmd = 'sudo iptables -I FORWARD 1 -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port)
                    print('$> ' + cmd, end='')
                    proc.stdin.write(cmd)

            print('$> exit')
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
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        print('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for cont_port in cont_ports:
                    print("Unblocking {} on {}:{}".format(self.vm, cont_ip, cont_ports))
                    cmd = 'sudo iptables -D FORWARD -d {} -p tcp --dport {} -j DROP\n'.format(cont_ip, cont_port)
                    print('$> ' + cmd, end='')
                    for _ in range(TIMES_TO_REMOVE):
                        proc.stdin.write(cmd)
            print("$> exit")
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def block_services(self, cfg, services):
        """
        Block instances of the application hosted on this DiegoCell from being able to reach and of the specified
        services.
        :param cfg: Configuration information about the environment.
        :param services: List of services to be blocked.
        :return: The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        print('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for service in services.values():
                    print("Targeting {} on {}".format(service.name, self.vm))
                    for (s_ip, s_port) in service.hosts:
                        cmd = 'sudo iptables -I FORWARD 1 -s {} -d {} -p tcp --dport {} -j DROP\n'\
                            .format(cont_ip, s_ip, s_port)
                        print('$> ' + cmd, end='')
                        proc.stdin.write(cmd)

            print('$> exit')
            proc.stdin.write('exit\n')
            proc.stdin.close()

            return proc.returncode

    def unblock_services(self, cfg, services):
        """
        Unblock instances of the application hosted on this DiegoCell from being able to reach and of the specified
        services.
        :param cfg: Configuration information about the environment.
        :param services: List of services to be blocked.
        :return: The returncode of the bosh ssh program.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'], self.vm)
        print('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            for cont_ip, cont_ports in self.containers.items():
                for service in services.values():
                    print("Unblocking {} on {}".format(service.name, self.vm))
                    for (s_ip, s_port) in service.hosts:
                        cmd = 'sudo iptables -D FORWARD -s {} -d {} -p tcp --dport {} -j DROP\n'\
                            .format(cont_ip, s_ip, s_port)
                        print('$> ' + cmd, end='')
                        for _ in range(TIMES_TO_REMOVE):
                            proc.stdin.write(cmd)

            print('$> exit')
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
        :param org: String; the cloud foundry organization the application is hosted in.
        :param space: String; the cloud foundry organization space the application is hosted in.
        :param appname: String; the name of the application deployment within cloud foundry.
        """

        self.org = org
        self.space = space
        self.appname = appname
        self.guid = None
        self.diego_hosts = {}
        self.services = {}

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
            for cont_ip, cont_ports in dc.containers.items():
                d_host.add_instance(cont_ip, cont_ports)
        else:
            self.diego_hosts[dc.ip] = dc

    def add_service(self, service):
        """
        Adds a service as a dependency of this app. It will merge any of the service information if the new service
        has the same type and name as one which is already present.
        :param service: Service; The new Service to add/merge.
        """
        sid = service.id()
        if sid in self.services:
            e_service = self.services[sid]
            assert e_service.user == service.user and e_service.pswd == service.pswd
            e_service.hosts |= service.hosts  # union the hosts
        else:
            self.services[service.id()] = service

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

    def find_services(self, cfg):
        """
        Discover all services bound to this application. This will use `cf env` and parse the output for VCAP_SERVICES.
        :param cfg: Configuration information about the environment.
        :return: The list of all services bound to this application.
        """
        cmd = '{} env {}'.format(cfg['cf']['cmd'], self.appname)
        print('> ' + cmd)
        with Popen(cmd.split(' '), stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            if proc.returncode:
                sys.exit("Failed to query application environment variables.")

            lines = proc.stdout.readlines()

        json_objs = extract_json(''.join(lines))
        if not json_objs:
            sys.exit("Error reading output from `cf env`")

        for obj in json_objs:
            if 'VCAP_SERVICES' not in obj:
                json_objs.remove(obj)

        if len(json_objs) != 1:
            sys.exit("Could not find VCAP_SERVICES in output.")

        services = json_objs[0]['VCAP_SERVICES']
        print(json.dumps(services, indent='  '))

        for service, sconfig in services.items():
            if service in cfg['service-whitelist']:
                continue

            for instance_cfg in sconfig:
                s = Service.from_service_info(service, instance_cfg)
                if s:
                    print(s)
                    self.add_service(s)

        return self.services

    def block(self, cfg):
        """
        Block access to this application on all its known hosts.
        :param cfg: Configuration information about the environment.
        :return: A returncode if any of the bosh ssh instances does not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.block(cfg)

            if ret:
                print("WARNING: could not block host {}.".format(dc.vm), file=sys.stderr)
                return ret

        return 0

    def unblock(self, cfg):
        """
        Unblock access to this application on all its known hosts. This will actually run the unblock commands multiple
        times, as defined by `TIMES_TO_REMOVE` to prevent issues if an application was blocked multiple times.
        :param cfg: Configuration information about the environment.
        :return: A returncode if any of the bosh ssh instances does not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.unblock(cfg)

            if ret:
                print("WARNING: could not unblock host {}.".format(dc.vm), file=sys.stderr)
                return ret

        return 0

    def block_services(self, cfg):
        """
        Block this application from accessing its services on all its known hosts.
        :param cfg: Configuration information about the environment.
        :return: A returncode if any of the bosh ssh instances does not return 0.
        """

        for dc in self.diego_hosts.values():
            ret = dc.block_services(cfg, self.services)

            if ret:
                print("WARNING: could not block all services on host {}".format(dc.vm), file=sys.stderr)
                return ret

        return 0

    def unblock_services(self, cfg):
        """
        Unblock this application from accessing its services on all its known hosts.
        :param cfg: Configuration information about the environment.
        :return: A returncode if any of the bosh ssh instances does not return 0.
        """
        for dc in self.diego_hosts.values():
            ret = dc.unblock_services(cfg, self.services)

            if ret:
                print("WARNING: could not unblock all services on host {}.".format(dc.vm), file=sys.stderr)
                return ret

        return 0

    def save(self, filename, overwrite=False):
        """
        Save all known hosts and services to a json file. This allows for the same hosts that were blocked to be
        unblocked even if cloud foundry moves application instances to a different container or diego-cell.
        :param filename: String; The name of the file to save the json object to.
        :param overwrite: bool; If true, overwrite the entire file instead of appending this object to the file.
        """
        if overwrite:
            j = {}
        else:
            try:
                with open(filename, 'r') as file:
                    j = json.load(file)
            except FileNotFoundError:
                j = {}

        if self.id() in j:
            japp = j[self.id()]
            assert self._validate_japp(japp)
        else:
            japp = {
                'appname': self.appname,
                'org': self.org,
                'space': self.space,
                'diego_hosts': {},
                'services': {}
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

        for sid, service in self.services.items():
            if sid in japp['services']:
                jsrv = japp['services'][sid]
                assert self._validate_jservice(jsrv)
                nhosts = set([tuple(x) for x in jsrv['hosts']]) | service.hosts
                jsrv['hosts'] = list(nhosts)
            else:
                japp['services'][sid] = {
                    'type': service.type,
                    'name': service.name,
                    'user': service.user,
                    'pswd': service.pswd,
                    'hosts': list(service.hosts)
                }

        j[self.id()] = japp

        with open(filename, 'w') as file:
            json.dump(j, file, indent=2)

    def load(self, filename, readonly=False):
        """
        Load a json file of known hosts and services. This allows for the same hosts that were blocked to be unblocked
        even if cloud foundry moves application instances to a different container or diego-cell. This will remove the
        entries for the specific app from the json file if `readonly` is `False`.
        :param filename: String; The name of the json file to load information from.
        :param readonly: bool; Whether we should remove the entries this specific app or leave the file as it was.
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

        for jservice in japp['services'].values():
            assert self._validate_jservice(jservice)
            hosts = set([tuple(x) for x in jservice['hosts']])
            service = Service(jservice['type'], jservice['name'], jservice['user'], jservice['pswd'], hosts)
            self.add_service(service)

        if not readonly:
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
        :param jdc: Dictionary object to validate.
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

    def _validate_jservice(self, jservice):
        """
        Quick way to verify a dictionary represenation of a service is valid. This is used to validate json information.
        :param jservice: Dictionary object to validate.
        :return: Whether it is a valid service representation.
        """
        service = self.services.get('{}:{}'.format(jservice['type'], jservice['name']))  # TODO: fix code duplication!
        return \
            service is None or (
                service.user == jservice['user'] and
                service.pswd == jservice['pswd'] and
                jservice['hosts'] is not None
            )

    def _find_guid(self, cfg):
        """
        Find the GUID of an application using cloud foundry's CLI interface. The GUID acts as a unique identifier for
        the application which we can then use to find what containers are running it.
        :param cfg: Configuration information about the environment.
        :return: The application GUID.
        """
        cmd = '{} app {} --guid'.format(cfg['cf']['cmd'], self.appname)
        print('$ ' + cmd)
        with Popen(cmd.split(' '), stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            guid = proc.stdout.readline().rstrip('\r\n')
            if proc.returncode:
                sys.exit(
                    "Failed retrieving the GUID for the specified app. Make sure {} is in this space!".format(self.appname))

        self.guid = guid
        print(guid)
        return guid

    def _find_container_hosts(self, cfg):
        """
        Find the containers which host this application by using cfdot.
        :param cfg: Configuration information about the environment.
        :return: The diego-cells which host this app and their associated sub-containers.
        """
        cmd = '{} -e {} -d {} ssh {}'.format(cfg['bosh']['cmd'], cfg['bosh']['env'], cfg['bosh']['cf-dep'],
                                             cfg['bosh']['cfdot-dc'])
        print('$ ' + cmd)
        with Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=DEVNULL, encoding=DEFAULT_ENCODING) as proc:
            cmd = 'cfdot actual-lrp-groups | grep --color=never {}\nexit\n'.format(self.guid)
            print('$> ' + cmd, end='')
            stdout, _ = proc.communicate(input=cmd, timeout=30)
            if proc.returncode:
                sys.exit("Failed retrieving LRP data from {}".format(cfg['bosh']['cfdot-dc']))

            json_objs = extract_json(stdout)
            for obj in json_objs:
                instance = obj['instance']

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
    cmd = '{} target -o {} -s {}'.format(cfg['cf']['cmd'], org, space)
    print('$ ' + cmd)
    return call(cmd.split(' '), stdout=DEVNULL, stderr=DEVNULL)


def extract_json(string):
    """
    Extract JSON from a string by scanning for the start `{` and end `}`. It will extract this from a string and then
    load it as a JSON object. If multiple json objects are detected, it will create a list of them. If no JSON is found,
    then None will be returned.
    :param string: String; String possibly containing one or more JSON objects.
    :return: Optional(list(dict[String, String)); A list of JSON objects or None.
    """
    depth = 0
    objstrs = []
    for index, char in enumerate(string):
        if char == '{':
            depth += 1

            if depth == 1:
                start = index
        elif char == '}' and depth > 0:
            depth -= 1

            if depth == 0:
                objstrs.append(string[start:index+1])

    if len(objstrs) <= 0:
        return None

    objs = []
    for s in objstrs:
        try:
            objs.append(json.loads(s))
        except json.JSONDecodeError:
            # ignore it and move on
            pass
    return objs


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
        app.save(DISCOVERY_FILE, overwrite=True)
    else:
        sys.exit("UNKNOWN OPTION!")

    print("\n=======\n Done!\n=======")


if __name__ == '__main__':
    main()