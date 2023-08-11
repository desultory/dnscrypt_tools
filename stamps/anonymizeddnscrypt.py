__version__ = '0.2.2'

from stamps.base import BaseStamp


class AnonymizedDNSCrypt(BaseStamp):
    has_props = False

    def parse_consumable_data(self):
        self.parse_address()
