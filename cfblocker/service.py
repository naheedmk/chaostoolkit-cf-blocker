import re
import sys
from socket import gethostbyname as dnslookup


class Service:
    """
    This represents a service which is bound to the application through cloud foundry. It contains information about the
    service such as where it is hosted and what ports it is accessed through as well as general service information like
    the username and password, service name, and service type.
    """

    @staticmethod
    def from_service_info(service_type, service_config):
        """
        Given a service configuration object and the name of the service, extract the hosts and username/password
        (if relevant).
        :param service_type: Name of the service the configuration is for, e.g. are 'p-mysql' or 'p-config-server'.
        :param service_config: Configuration object from VCAP_SERVICES for the provided service. Note, it is for one instance.
        :return: TODO: determine what exactly we want to return.
        """
        stype = service_type
        name = service_config['name']
        user = None
        pswd = None
        hosts = set()

        credentials = service_config.get('credentials', None)

        if stype == 'p-config-server':
            user = credentials['client_id']
            pswd = credentials['client_secret']
            match = re.match(r'https://([a-z0-9_.-]+):?(\d+)?', credentials['uri'])
            ip = dnslookup(match[1])  # from my testing, the diego-cells *should* find the same values
            port = match[2] or '443'
            hosts.add((ip, port))
        elif stype == 'T-Logger':
            match = re.match(r'syslog://([a-z0-9_.-]+):(\d+)', credentials['syslog_drain_url'])
            ip = dnslookup(match[1])
            hosts.add((ip, match[2]))
        elif stype == 'p-mysql':
            user = credentials['username']
            pswd = credentials['password']
            hosts.add((credentials['hostname'], credentials['port']))
        elif stype == 'p-rabbitmq':
            user = credentials['username']
            pswd = credentials['password']
            for pconfig in credentials['protocols'].values():
                port = pconfig['port']
                for host in pconfig['hosts']:
                    hosts.add((host, port))
        else:
            print("Unrecognized service '{}'".format(stype), file=sys.stderr)
            return None

        return Service(stype, name, user, pswd, hosts)

    def __init__(self, type, name, user, pswd, hosts):
        """
        Initialize a new Service representation.
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

    def __iter__(self):
        """
        Iterate over the hosts of this service.
        :return: An iterator over the hosts of this service.
        """
        return self.hosts.__iter__()

    def __contains__(self, item):
        """
        Check if this Service contains a given host.
        :param item: The Host (IP, Port) tuple.
        :return: Whether it is a known host of this service.
        """
        return item in self.hosts

    def __len__(self):
        """
        Count the number of known hosts for this service.
        :return: The number of known hosts for this service.
        """
        return len(self.hosts)

    def __hash__(self):
        """
        A unique identifier for this Service based on its type and name.
        :return: A unique hash for this Service.
        """
        return hash(self.id())

    def __delitem__(self, host):
        """
        Remove a known host from this service.
        :param host: The (IP, Port) of the host to be removed.
        """
        return self.hosts.__delitem__(host)

    def add(self, ip, port):
        """
        Add a new host for this Service.
        :param ip: The host's IP address.
        :param port: The port the service is listening to.
        """
        self.hosts.add((ip, port))

    def __repr__(self):
        return 'Service({}, {}, {}, {}, {})'.format(self.type, self.name, self.user, self.pswd, self.hosts)

    def id(self):
        """
        Generate a unique identifier for this service based on its name and type.
        :return: A unique identifier for this service.
        """
        return '{}:{}'.format(self.type, self.name)
