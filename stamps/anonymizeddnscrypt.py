__version__ = '0.2.0'

from stamps.base import BaseStamp


class AnonymizedDNSCrypt(BaseStamp):
    has_props = False

    def parse_consumable_data(self):
        self.parse_address()

        if self.consumable_data:
            self.logger.warning("Unconsumed data: %s", self.consumable_data)

