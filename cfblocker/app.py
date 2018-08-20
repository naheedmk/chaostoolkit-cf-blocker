import sys
import json

from cfblocker import DEFAULT_ENCODING
from cfblocker.diegohost import DiegoHost
from cfblocker.service import Service
from cfblocker.util import extract_json
from subprocess import Popen, PIPE, DEVNULL


class App:
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

    def __repr__(self):
        return 'App({}:{}:{})'.format(self.org, self.space, self.appname)

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

    def serialize(self, obj=None):
        """
        Convert this class into a dictionary representation of itself.
        :param obj: A dictionary to serialize into and merge information with.
        :return: A dictionary representation of this object.
        """
        if obj is None:
            obj = {}

        if self.id() in obj:
            app = obj[self.id()]
            assert self._validate_japp(app)
        else:
            app = {
                'appname': self.appname,
                'org': self.org,
                'space': self.space,
                'diego_hosts': {},
                'services': {}
            }

        for dc in self.diego_hosts.values():
            if dc.ip in app['diego_hosts']:
                jdc = app['diego_hosts'][dc.ip]
                assert jdc['vm'] == dc.vm
                assert jdc['ip'] == dc.ip
            else:
                jdc = {'ip': dc.ip, 'vm': dc.vm, 'containers': {}}

            for cont_ip, cont_ports in dc.containers.items():
                jports = set(jdc.get(cont_ip, []))
                jdc['containers'][cont_ip] = list(jports | cont_ports)

                app['diego_hosts'][dc.ip] = jdc

        for sid, service in self.services.items():
            if sid in app['services']:
                jsrv = app['services'][sid]
                assert self._validate_jservice(jsrv)
                nhosts = set([tuple(x) for x in jsrv['hosts']]) | service.hosts
                jsrv['hosts'] = list(nhosts)
            else:
                app['services'][sid] = {
                    'type': service.type,
                    'name': service.name,
                    'user': service.user,
                    'pswd': service.pswd,
                    'hosts': list(service.hosts)
                }

        obj[self.id()] = app
        return obj

    @staticmethod
    def deserialize(obj, org, space, appname, readonly=False):
        """
        Convert a dictionary representation of this class into an instance of this class.
        :return: An instance of this class.
        """
        self = App(org, space, appname)
        app = obj.get(self.id(), None) if readonly else obj.pop(self.id(), None)

        if app is None:
            return False

        assert self._validate_japp(app)

        for diego_ip, jdc in app['diego_hosts'].items():
            assert self._validate_jdc(jdc)
            dc = DiegoHost(diego_ip)
            dc.vm = jdc['vm']

            for cont_ip, cont_ports in jdc['containers'].items():
                dc.add_instance(cont_ip, set(cont_ports))

            self.add_diego_cell(dc)

        for service in app['services'].values():
            assert self._validate_jservice(service)
            hosts = set([tuple(x) for x in service['hosts']])
            self.add_service(Service(
                service['type'],
                service['name'],
                service['user'],
                service['pswd'],
                hosts
            ))

        return self

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
