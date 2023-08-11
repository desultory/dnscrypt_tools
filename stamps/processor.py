__version__ = '0.1.0'


from zen_custom import loggify
from stamps.snatcher import Snatcher


@loggify
class Processor:
    def __init__(self, snatcher=None, ipv6=True, autofetch=True, *args, **kwargs):
        self.ipv6 = ipv6
        self.snatcher = snatcher or Snatcher(logger=self.logger, ipv6=self.ipv6)

        if autofetch:
            self.snatcher.fetch()

    def get_all_ips(self):
        ips = set()
        for stamp in self.iterate_stamps():
            ips = ips | stamp.address
        return ips

    def iterate_stamps(self):
        for source in self.snatcher.sources.values():
            for stamp in source['stamps']:
                yield stamp
