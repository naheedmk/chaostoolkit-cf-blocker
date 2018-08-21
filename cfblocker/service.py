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
        :param service_type: String; Name of the service the configuration is for, e.g. are 'p-mysql' or 'p-config-server'.
        :param service_config: Optional[Dict[String, any]]; Configuration object from VCAP_SERVICES for the provided service. Note, it is for one instance.
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
            hosts.add((ip, 'tcp', port))
        elif stype == 'T-Logger':
            match = re.match(r'syslog://([a-z0-9_.-]+):(\d+)', credentials['syslog_drain_url'])
            ip = dnslookup(match[1])
            hosts.add((ip, 'tcp', match[2]))
        elif stype == 'p-mysql':
            user = credentials['username']
            pswd = credentials['password']
            hosts.add((credentials['hostname'], 'tcp', credentials['port']))
        elif stype == 'p-rabbitmq':
            user = credentials['username']
            pswd = credentials['password']
            for pconfig in credentials['protocols'].values():
                port = pconfig['port']
                for host in pconfig['hosts']:
                    hosts.add((host, 'tcp', port))
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
        :param hosts: Set[(String, String)]; Set of (IP, Port) tuples for where this service is hosted.
        """
        self.type = type
        self.name = name
        self.user = user
        self.pswd = pswd
        self.hosts = hosts

    def __iter__(self):
        """
        Iterate over the hosts of this service.
        :return: Iter; An iterator over the hosts of this service.
        """
        return self.hosts.__iter__()

    def __contains__(self, item):
        """
        Check if this Service contains a given host.
        :param item: (String, String); The Host (IP, Port) tuple.
        :return: bool; Whether it is a known host of this service.
        """
        return item in self.hosts

    def __len__(self):
        """
        Count the number of known hosts for this service.
        :return: int; The number of known hosts for this service.
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
        :param host: (String, String); The (IP, Port) of the host to be removed.
        """
        return self.hosts.__delitem__(host)

    def add(self, ip, port):
        """
        Add a new host for this Service.
        :param ip: String; The host's IP address.
        :param port: String; The port the service is listening to.
        """
        self.hosts.add((ip, port))

    def __repr__(self):
        return 'Service({}, {}, {}, {}, {})'.format(self.type, self.name, self.user, self.pswd, self.hosts)

    def id(self):
        """
        Generate a unique identifier for this service based on its name and type.
        :return: String; A unique identifier for this service.
        """
        return '{}:{}'.format(self.type, self.name)

    def serialize(self, obj=None):
        """
        Convert this class into a dictionary representation of itself.
        :param obj: Dict[String, any]; A dictionary to serialize into and merge information with. The keys should be in the form `servicetype:servicename`.
        :return: Dict[String, any]; A dictionary representation of this object.
        """
        if obj is None:
            obj = {}

        sid = self.id()
        if sid in obj:
            jsrv = obj[sid]
            assert self.user == jsrv['user'] and self.pswd == jsrv['pswd'] and jsrv['hosts']
            nhosts = set([tuple(x) for x in jsrv['hosts']]) | self.hosts
            jsrv['hosts'] = [list(x) for x in nhosts]
        else:
            obj[sid] = {
                'type': self.type,
                'name': self.name,
                'user': self.user,
                'pswd': self.pswd,
                'hosts': [list(x) for x in self.hosts]
            }

        return obj

    @staticmethod
    def deserialize(obj, sid):
        """
        Convert a dictionary representation of this class into an instance of this class.
        :param obj: Dict[String, any]; Dictionary to deserialize from in the form {"type:name": {Service}, ...}.
        :param sid: String; The service `type:name` identifier string.
        :return: Service; An instance of this class.
        """
        service = obj[sid]

        return Service(
            service['type'],
            service['name'],
            service['user'],
            service['pswd'],
            set([tuple(x) for x in service['hosts']])
        )
