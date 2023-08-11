__version__ = "0.1.0"

from stamps.base import BaseStamp


class DNSCrypt(BaseStamp):
    additional_parameters = ['public_key', 'provider_name']

    def parse_consumable_data(self):
        """
        Override BaseStamp.parse_consumable_data
        """
        self.parse_address()
        self.public_key = self.consume_lp(decode=False)
        self.provider_name = self.consume_lp()

