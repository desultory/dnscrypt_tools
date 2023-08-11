__version__ = '0.1.3'


from zen_custom import loggify
from stamps.snatcher import Snatcher


@loggify
class Processor:
    def __init__(self, snatcher=None, autofetch=True, *args, **kwargs):
        self.snatcher = snatcher or Snatcher(logger=self.logger)

        if autofetch:
            self.snatcher.fetch()

    def get_all_ips(self):
        """
        Iterates over all stamps and sources in the snatcher.
        Returns 3 sets, the first containing source ips, the second containing ipv4 ips and the third containing ipv6 ips.
        """
        from ipaddress import IPv4Address, IPv6Address
        source_ips = set()
        ipv4_ips = set()
        ipv6_ips = set()

        for source in self.snatcher.sources.values():
            source_ips.add(source['source_ip'])

        for stamp in self.iterate_stamps():
            if not isinstance(stamp.address, set):
                raise TypeError(f'Address is not a set: {stamp.address}')
            for address in stamp.address:
                if isinstance(address, IPv4Address):
                    ipv4_ips.add(address)
                elif isinstance(address, IPv6Address):
                    ipv6_ips.add(address)
                else:
                    self.logger.error("Unknown address type for address: %s", address)
                    raise TypeError(f'Unknown address type: {type(address)}')
        return source_ips, ipv4_ips, ipv6_ips

    def iterate_stamps(self):
        for source in self.snatcher.sources.values():
            for stamp in source['stamps']:
                yield stamp
