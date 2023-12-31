__version__ = '0.2.2'

from zen_custom import loggify, threaded
from stamps.base import BaseStamp, DisabledStampType, BrokenStampError


@loggify
class Snatcher:
    """
    Does partial parsing of a dnscrypt-proxy.toml file and fetches the latest resolver list from the sources
    """

    ip_settings = ['ipv4_servers', 'ipv6_servers', 'block_ipv6']
    source_settings = ['dnscrypt_servers', 'doh_servers', 'odoh_servers']
    require_options = ['require_dnssec', 'require_nolog', 'require_nofilter']

    def __init__(self, dnscrypt_config='dnscrypt-proxy.toml', source_dir='resolver_sources', *args, **kwargs):
        self.dnscrypt_config_file = dnscrypt_config
        self.source_dir = source_dir
        self.sources = {}

        self.load_config()

    def load_config(self):
        """
        Reads the dnscrypt-proxy.toml file
        """
        from tomllib import load
        with open(self.dnscrypt_config_file, 'rb') as f:
            self.config = load(f)
        self.logger.info("Loaded config file: %s", self.dnscrypt_config_file)

        ip_settings = {}
        # Parse ip settings
        for field in self.ip_settings:
            ip_settings[field] = self.config.get(field, True)

        if not ip_settings['ipv4_servers'] and not ip_settings['ipv6_servers']:
            self.logger.error("Either IPv4 or IPv6 servers must be enabled in the config file")
            raise ValueError("All IP versions are disabled in the config file")

        self.ip_settings = ip_settings

        source_settings = {}
        # Parse source settings
        for field in self.source_settings:
            source_settings[field] = self.config[field]

        self.source_settings = source_settings

        require_options = {}
        # Parse require options
        for field in self.require_options:
            require_options[field] = self.config.get(field, False)

        self.require_options = require_options

    @threaded
    def get_source(self, url, fresh=False):
        """
        Gets a source from the specified url
        """
        from urllib import request
        from urllib.error import URLError

        if not url.endswith('.md'):
            self.logger.error("Source must be a .md file")
            return

        source_name = f"{self.source_dir}/{url.split('/')[2]}-{ url.split('/')[-1]}"

        try:
            self.logger.debug("Fetching source: %s", url)
            response = request.urlopen(url)
            source_ip = response.fp.raw._sock.getpeername()[0]
            self.logger.info("Fetched source '%s' from IP: %s", url, source_ip)
        except URLError as e:
            self.logger.error("Failed to fetch source '%s': %s" % (url, e.reason))
            return

        raw_content = response.read().decode('utf-8').splitlines()
        content = [line for line in raw_content if line.strip()]

        self.sources[source_name] = {}
        self.sources[source_name]['source_ip'] = source_ip
        self.sources[source_name]['content'] = content

    def fetch(self, fresh=False):
        """
        Fetches the latest resolver list from the sources
        """
        for source, data in self.config['sources'].items():
            for url in data['urls']:
                self.get_source(url, fresh=fresh)

        for thread, exception in self._threads:
            while not exception.empty():
                e = exception.get()
                self.logger.exception("Exception occured while fetching sources: %s", e)
            thread.join()

        self.process_stamps()

    def process_stamps(self):
        """
        Processes the stamps from the sources
        """
        for source, data in self.sources.items():
            self.sources[source]['stamps'] = []
            self.logger.info("Processing DNS stamps in source: %s", source)
            for line in data['content']:
                if line.startswith('sdns://'):
                    try:
                        stamp = BaseStamp(line, source_settings=self.source_settings, require_options=self.require_options, _log_init=False, logger=self.logger, ip_settings=self.ip_settings)
                    except DisabledStampType as e:
                        self.logger.warning("Skipping stamp, disabled stamp type: %s", e)
                        continue
                    except BrokenStampError as e:
                        self.logger.error("Skipping stamp, broken stamp: %s", e)
                        continue
                    self.sources[source]['stamps'].append(stamp)

        for thread, exception in BaseStamp._threads:
            while not exception.empty():
                e = exception.get()
                self.logger.error("Exception occured while processing stamps: %s", e)
            thread.join()

