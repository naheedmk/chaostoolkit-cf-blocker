import sys
from socket import gethostbyname as dnslookup


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
