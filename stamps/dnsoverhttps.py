__version__ = "0.2.0"

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

        if self.consumable_data:
            self.logger.warning("Unconsumed data: %s", self.consumable_data)
