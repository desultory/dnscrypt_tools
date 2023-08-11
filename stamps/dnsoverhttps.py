__version__ = "0.2.2"

from stamps.base import BaseStamp


class DNSOverHTTPS(BaseStamp):
    additional_parameters = ['hostname', 'path']

    def parse_consumable_data(self):
        """
        Override for the base stamp consume method.
        """
        self.hostname = self.consume_lp()
        self.hashes = self.consume_vlp(decode=False)
        self.parse_address()
        self.path = self.consume_lp()
