__version__ = '0.1.2'


from zen_custom import loggify
from stamps.snatcher import Snatcher


@loggify
class Processor:
    def __init__(self, snatcher=None, autofetch=True, *args, **kwargs):
        self.snatcher = snatcher or Snatcher(logger=self.logger)

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
