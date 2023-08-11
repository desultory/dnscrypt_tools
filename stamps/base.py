__version___ = "0.1.4"

from zen_custom import loggify, threaded
from enum import Enum


DEFAULT_IP_SETTINGS = {'ipv4_servers': True, 'ipv6_servers': True, 'block_ipv6': False}


class DNSCryptStampType(Enum):
    """
    DNSCrypt stamp type
    """
    Plain = 0x00
    DNSCrypt = 0x01
    DNSOverHTTPS = 0x02
    DNSOverTLS = 0x03
    DNSOverQUIC = 0x04
    ObliviousDOH = 0x05
    AnonymizedDNSCrypt = 0x81
    ObliviousDOHR = 0x85


class DNSCryptStampOption(Enum):
    """
    DNSCrypt stamp option, with the value of the bit in the options field
    """
    DNSSEC = 0x01
    NOLOGS = 0x02
    NOFILTER = 0x04


@loggify
class BaseStamp:
    """
    Base class representing a DNSCrypt stamp
    has_props determines whether or not stamps will have options, they are skipped otherwise
    The bsae parameters are shared between all stamps currently
    Additional parameters can be defined if making a subclass.

    Based on the StampType enum, the stamp type is determined and the appropriate class is returned
    The file should be the name of the stamp type, in lowercase

    ip_settings is a dictionary of settings for resolving addresses, like DEFAULT_IP_SETTINGS.
    When used with the snatcher, this config will be read from the dnscrypt-proxy.toml file
    """
    has_props = True
    default_port = 443

    base_parameters = ['address', 'port']
    additional_parameters = []
    _threads = []  # Tracks threads in @threaded methods, make it a class variable

    def __new__(cls, sdns=None, *args, **kwargs):
        """
        Return a stamp object based on the sdns field
        Determine the type and options, return a specialed stamp object
        """
        from importlib import import_module
        if not sdns:
            return super().__new__(cls)

        decoded_data = cls.decode_stamp(sdns)
        stamp_type = cls.determine_stamp_type(decoded_data)
        return super().__new__(getattr(import_module(f"stamps.{stamp_type.lower()}"), stamp_type))

    def __init__(self, sdns=None, resolve=True, ip_settings=DEFAULT_IP_SETTINGS, *args, **kwargs):
        self.resolve = resolve
        self.ip_settings = ip_settings
        for option in DNSCryptStampOption:
            setattr(self, option.name.lower(), kwargs.get(option.name.lower(), False))  # Set the option attributes, defaulting to False

        self.address = set()  # Make a set, dns entries can have multiple addresses

        self.sdns = self.decode_stamp(sdns)
        if sdns:
            if self.has_props:
                self.parse_options()
            else:
                self.logger.debug("Stamp type %s does not have options", self.__class__.__name__)
            self.parse_sdns()

    @classmethod
    def decode_stamp(cls, b64_stamp_data):
        """
        Decode the base64 encoded DNSCrypt stamp
        """
        from base64 import urlsafe_b64decode

        def _pad_b64(b64_data):
            """
            Pad the base64 data to a multiple of 4
            """
            # Check if the base64 data is already a multiple of 4
            if len(b64_data) % 4 == 0:
                return b64_data
            # Pad the base64 data to a multiple of 4
            return b64_data + "=" * (4 - (len(b64_data) % 4))

        if b64_stamp_data.startswith("sdns://"):
            b64_stamp_data = b64_stamp_data[7:].strip()  # Remove the sdns:// prefix and strip

        # Replace - and _ with ''
        b64_stamp_data = b64_stamp_data.replace("-", "+").replace("_", "/")

        padded_b64_data = _pad_b64(b64_stamp_data)

        return urlsafe_b64decode(padded_b64_data)

    @classmethod
    def determine_stamp_type(cls, stamp_data):
        """
        Determine the stamp type, based on the stamp header
        Returns a class corresponding to the stamp type
        """
        header_value = stamp_data if len(stamp_data) == 1 else stamp_data[0]

        for stamp_type in DNSCryptStampType:
            if stamp_type.value == header_value:
                return stamp_type.name
        raise ValueError("Invalid stamp type: %s" % header_value)

    def _parse_ipv6_address(self, address):
        """
        Parse an IPv6 address
        """
        if not self.ip_settings['ipv6_servers'] or self.ip_settings['block_ipv6']:
            raise ValueError("IPv6 servers are disabled")

        from ipaddress import IPv6Address, AddressValueError
        address, port = address[1:].split(']')  # Remove the leading [ and split the port

        try:
            self.port = int(port)
        except ValueError:
            self.port = self.default_port

        try:
            self.address.add(IPv6Address(address))
        except AddressValueError:
            raise ValueError("Invalid IPv6 address: %s" % address)

    def _parse_ipv4_address(self, address):
        """
        Parse an IPv4 address
        """
        if not self.ip_settings['ipv4_servers']:
            raise ValueError("IPv4 servers are disabled")

        from ipaddress import IPv4Address, AddressValueError

        try:
            address, port = address.split(':')
        except ValueError:
            address = address
            port = self.default_port
        finally:
            try:
                self.port = int(port)
            except ValueError:
                self.port = self.default_port

        try:
            self.address.add(IPv4Address(address))
        except AddressValueError:
            if self.resolve:
                self.resolve_address(address)
            else:
                raise ValueError("Invalid IPv4 address: %s" % address)

    @threaded
    def resolve_address(self, address):
        """
        Resolve the address to an IP address
        """
        from socket import getaddrinfo, AF_INET, AF_INET6, SOCK_STREAM, gaierror

        if self.ip_settings['ipv6_servers']:
            addr_family = AF_INET6
        elif self.ip_settings['ipv4_servers']:
            addr_family = AF_INET
        else:
            raise ValueError("No IP versions are enabled")

        try:
            address_info = getaddrinfo(address, self.port, addr_family, SOCK_STREAM)
        except gaierror as e:
            if addr_family == AF_INET6 and self.ip_settings['ipv4_servers']:
                self.logger.warning("Could not resolve IPv6 address %s: %s", address, e)
                self.logger.info("Trying to resolve IPv4 address")
                address_info = getaddrinfo(address, self.port, AF_INET, SOCK_STREAM)
            else:
                raise ValueError("Could not resolve IPv4 address %s: %s" % (address, e))

        for address in address_info:
            self.address.add(address[4][0])

    def parse_address(self):
        """
        Consumes a length-value pair and sets the address and port attributes
        """
        if not self.ip_settings['ipv4_servers'] and not self.ip_settings['ipv6_servers']:
            raise ValueError("No IP versions are enabled")

        address = self.consume_lp()
        if address.startswith('[') and ']' in address:
            if self.ip_settings['block_ipv6']:
                raise ValueError("IPv6 servers are blocked")
            elif self.ip_settings['ipv6_servers']:
                self._parse_ipv6_address(address)
            else:
                self.logger.warning("IPv6 servers are disabled, but IPv6 address %s was found", address)
                raise ValueError("IPv6 servers are disabled")
        else:
            self._parse_ipv4_address(address)

    def parse_options(self):
        """
        Parse the options.
        They are stored after the type as a little-endian 64-bit integer.
        """
        from struct import unpack

        options = unpack('<Q', self.sdns[1:9])[0]  # Unpack the options as a 64-bit integer

        for option in DNSCryptStampOption:
            if options & option.value:
                setattr(self, option.name.lower(), True)  # Set the option attributes

    def parse_sdns(self):
        """
        Parse the sdns field
        """
        self.logger.debug("Parsing sdns field: %s", self.sdns)
        offset = 9 if self.has_props else 1
        self.consumable_data = self.sdns[offset:]  # Remove the header and options
        self.logger.debug("Consumable data: %s", self.consumable_data)

        self.parse_consumable_data()
        if self.consumable_data:
            self.logger.warning("Consumable data remains after parsing: %s", self.consumable_data)

    def parse_consumable_data(self):
        """
        Parse the consumable data
        """
        while self.consumable_data:
            self.consume()  # Monch

    @staticmethod
    def parse_variable_length(length):
        """
        Parse variable length data
        """
        # Check if the high bit is set
        if length & 0x80:
            # strip the high bit
            length = length & 0x7F
        return length

    def consume_lp(self, length=0, decode=True):
        """
        Consume a length-value pair
        """
        length = self.consumable_data[0] if not length else length
        self.logger.log(5, "Consuming length: %s", length)

        value = self.consumable_data[1:length + 1]
        self.consumable_data = self.consumable_data[length + 1:]
        self.logger.debug("Consumed length-value pair: %s", value)

        return value.decode() if decode else value

    def consume_vlp(self, decode=True):
        """
        Consume a variable length length-value pair
        """
        data = []
        break_me = False
        while True:
            if break_me:
                break

            length = self.consumable_data[0]
            if length == 0:
                self.logger.log(5, "Found null length")
                self.consumable_data = self.consumable_data[1:]
                break
            elif length & 0x80:
                length = length & 0x7F
            else:
                break_me = True

            self.logger.debug("Consuming variable length: %s", length)
            data.append(self.consume_lp(length, decode))

        return data

    def consume(self):
        """
        Munch on the consumable data
        """
        self.logger.debug("Munching on: %s", self.consumable_data)
        self.consumable_data = self.consumable_data[1:]

    def __str__(self):
        """
        Convert the DNSCrypt stamp to a string
        """
        out_str = f"{self.__class__.__name__}:\n"
        for option in DNSCryptStampOption:
            out_str += "  %s: %s\n" % (option.name, getattr(self, option.name.lower()))

        parameters = self.base_parameters + self.additional_parameters

        for parameter in parameters:
            if hasattr(self, parameter):
                if isinstance(getattr(self, parameter), set):
                    out_str += "  %s: %s\n" % (parameter, ', '.join([str(item) for item in getattr(self, parameter)]))
                else:
                    out_str += "  %s: %s\n" % (parameter, getattr(self, parameter))

        return out_str

