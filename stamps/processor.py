__version__ = '0.3.0'


from zen_custom import loggify
from stamps.snatcher import Snatcher


@loggify
class Processor:
    """
    Processes the data from the snatcher and generates nftables rules.
    """

    required_config_keys = ['dnscrypt_table', 'dnscrypt_table_type', 'dnscrypt_chain_name', 'dnscrypt_hook_chain', 'dnscrypt_source_chain', 'dnscrypt_port_chain', 'dnscrypt_proxy_clients']
    optional_config_keys = ['nat_chain_type', 'nat_chain_name', 'nat_set_name', 'dnscrypt_nftables_rulefile', 'dnscrypt_config_file']

    def __init__(self, snatcher=None, autofetch=True, config_file='config.toml', print_output=False, *args, **kwargs):
        self.config_file = config_file
        self.print_output = print_output

        self.load_config()

        if isinstance(snatcher, Snatcher):
            self.logger.info('Using provided snatcher')
            self.snatcher = snatcher
        else:
            kwargs = {'logger': self.logger}
            if self.dnscrypt_config_file:
                kwargs['dnscrypt_config'] = self.dnscrypt_config_file
            self.snatcher = Snatcher(**kwargs)

        if autofetch:
            self.snatcher.fetch()

    def load_config(self):
        """
        Reads self.config_file and loads it into self.config.
        """
        from tomllib import load
        with open(self.config_file, 'rb') as f:
            self.config = load(f)
        self.logger.info('Loaded config from %s', self.config_file)

        for config_item in self.required_config_keys:
            if config_item not in self.config:
                raise ValueError(f'Config item missing: {config_item}')
            else:
                setattr(self, config_item, self.config[config_item])

        for config_item in self.optional_config_keys:
            if config_item not in self.config:
                self.logger.warning('Optional config item missing: %s', config_item)
                setattr(self, config_item, None)
            else:
                setattr(self, config_item, self.config[config_item])

    def generate_nftables_sets(self):
        """
        Generates nftables rule sets using information in the snatcher.
        """
        from ipaddress import IPv4Address, IPv6Address, AddressValueError
        source_ips, ipv4_ips, ipv6_ips = self._get_all_ips()

        for source in source_ips:
            try:
                source_ip = IPv4Address(source)
                ipv4_ips.add(source_ip)
            except AddressValueError:
                source_ip = IPv6Address(source)
                ipv6_ips.add(source_ip)
            self.logger.debug('Source IP: %s', source_ip)

        ports = self._get_all_ports()

        dnscrypt_v4_clients = set()
        dnscrypt_v6_clients = set()

        for dnscrypt_client in self.dnscrypt_proxy_clients:
            try:
                client_ip = IPv4Address(dnscrypt_client)
                dnscrypt_v4_clients.add(client_ip)
            except AddressValueError:
                client_ip = IPv6Address(dnscrypt_client)
                dnscrypt_v6_clients.add(client_ip)
            self.logger.debug('DNSCrypt client IP: %s', client_ip)

        out_str = "#!/sbin/nft -f\n\n"

        # Make variable definitions
        if dnscrypt_v4_clients:
            out_str += f"define dnscrypt_v4_clients = {{ {', '.join([str(ip) for ip in dnscrypt_v4_clients])} }}\n"
        if dnscrypt_v6_clients:
            out_str += f"define dnscrypt_v6_clients = {{ {', '.join([str(ip) for ip in dnscrypt_v6_clients])} }}\n"

        # Start by making the table header
        out_str += f"\ntable {self.dnscrypt_table_type} {self.dnscrypt_table} {{\n"
        # Make the port set
        out_str += f"  set {self.dnscrypt_port_chain} {{\n"
        out_str += "    type inet_service\n"
        out_str += f"    elements = {{ {', '.join([str(port) for port in ports])} }}\n"
        out_str += "  }\n"
        # make the ipv4 source set
        out_str += f"  set {self.dnscrypt_source_chain}_ipv4 {{\n"
        out_str += "    type ipv4_addr\n"
        out_str += f"    elements = {{ {', '.join([str(ip) for ip in ipv4_ips])} }}\n"
        out_str += "  }\n"
        # make the ipv6 source set
        out_str += f"  set {self.dnscrypt_source_chain}_ipv6 {{\n"
        out_str += "    type ipv6_addr\n"
        out_str += f"    elements = {{ {', '.join([str(ip) for ip in ipv6_ips])} }}\n"
        out_str += "  }\n"
        # Make the filter chain
        out_str += f"  chain {self.dnscrypt_chain_name} {{\n"
        out_str += f"    ip daddr @{self.dnscrypt_source_chain}_ipv4 tcp dport @{self.dnscrypt_port_chain} counter accept\n"
        out_str += f"    ip6 daddr @{self.dnscrypt_source_chain}_ipv6 tcp dport @{self.dnscrypt_port_chain} counter accept\n"
        out_str += f"    ip daddr @{self.dnscrypt_source_chain}_ipv4 udp dport @{self.dnscrypt_port_chain} counter accept\n"
        out_str += f"    ip6 daddr @{self.dnscrypt_source_chain}_ipv6 udp dport @{self.dnscrypt_port_chain} counter accept\n"
        # Add bootstrap servers
        for bootstrap_resolver in self.snatcher.config['bootstrap_resolvers']:
            resolver_ip, resolver_port = bootstrap_resolver.split(':')
            out_str += f'    ip daddr {resolver_ip} udp dport {resolver_port} counter accept comment "Bootstrap resolver"\n'
        out_str += "  }\n"
        # Add it to the appropriate hook
        out_str += f"  chain {self.dnscrypt_hook_chain} {{\n"
        if dnscrypt_v4_clients:
            out_str += f"    ip saddr $dnscrypt_v4_clients counter jump {self.dnscrypt_chain_name}\n"
        if dnscrypt_v6_clients:
            out_str += f"    ip6 saddr $dnscrypt_v6_clients counter jump {self.dnscrypt_chain_name}\n"
        out_str += "  }\n"
        out_str += "}\n"

        if dnscrypt_v4_clients:
            if not self.nat_chain_type or not self.nat_chain_name or not self.nat_set_name:
                raise ValueError('IPv4 clients specified but NAT chain not configured')
            out_str += f"table {self.nat_chain_type} {self.nat_chain_name} {{\n"
            out_str += f"  set {self.nat_set_name} {{\n"
            out_str += "    type ipv4_addr\n"
            out_str += "    flags interval\n"
            out_str += f"    elements = {{ {', '.join([str(ip) for ip in dnscrypt_v4_clients])} }}\n"
            out_str += "  }\n"
            out_str += "}\n"

        if self.print_output:
            print(out_str)

        if self.dnscrypt_nftables_rulefile is not None:
            with open(self.dnscrypt_nftables_rulefile, 'w') as f:
                f.write(out_str)
        else:
            self.logger.info('No rulefile specified, not writing to file')

    def _get_all_ips(self):
        """
        Iterates over all stamps and sources in the snatcher.
        Returns 3 sets, the first containing source ips, the second containing ipv4 ips and the third containing ipv6 ips.
        """
        if not self.snatcher.sources:
            raise ValueError('No sources in snatcher')

        source_ips = set()
        ipv4_ips = set()
        ipv6_ips = set()

        for source in self.snatcher.sources.values():
            source_ips.add(source['source_ip'])

        for stamp in self.iterate_stamps():
            ipv4_ips |= stamp.ipv4_servers
            ipv6_ips |= stamp.ipv6_servers

        return source_ips, ipv4_ips, ipv6_ips

    def _get_all_ports(self):
        """
        Iterates over all stamps in the snatcher.
        Returns a set containing all ports.
        """
        if not self.snatcher.sources:
            raise ValueError('No sources in snatcher')

        ports = set()

        for stamp in self.iterate_stamps():
            if not isinstance(stamp.port, int):
                raise TypeError(f'Port is not an int: {stamp.port}')
            ports.add(stamp.port)
        return ports

    def iterate_stamps(self):
        """
        Iterates over all stamps in the snatcher.
        """
        for source in self.snatcher.sources.values():
            for stamp in source['stamps']:
                yield stamp

    def __str__(self):
        return ''.join([str(stamp) for stamp in self.iterate_stamps()])

