import sys
from subprocess import Popen, DEVNULL, PIPE
from cfblocker import DEFAULT_ENCODING, TIMES_TO_REMOVE


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
        :return: Whether the container is in this Diego-cell.
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

    def __repr__(self):
        return 'DiegoHost({}:{})'.format(self.ip, self.vm)

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
