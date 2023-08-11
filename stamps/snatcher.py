__version__ = '0.1.0'

from zen_custom import loggify
from stamps.base import BaseStamp


@loggify
class Snatcher:
    def __init__(self, dnscrypt_config='dnscrypt-proxy.toml', source_dir='resolver_sources', ipv6=True, *args, **kwargs):
        self.dnscrypt_config_file = dnscrypt_config
        self.source_dir = source_dir
        self.sources = {}
        self.ipv6 = ipv6

        self.load_config()

    def load_config(self):
        """
        Reads the dnscrypt-proxy.toml file
        """
        from tomllib import load
        with open(self.dnscrypt_config_file, 'rb') as f:
            self.config = load(f)
        self.logger.info("Loaded config file: %s", self.dnscrypt_config_file)

    def _check_source_dir(self):
        """
        Checks if the source directory exists, if not, creates it.
        """
        from os.path import exists
        from os import mkdir
        if not exists(self.source_dir):
            mkdir(self.source_dir)
            self.logger.info("Created source directory: %s", self.source_dir)

    def read_source(self, filename):
        """
        Reads a source file and adds it to the list of sources
        """
        self.logger.info("Reading source file: %s", filename)
        with open(filename, 'r') as f:
            self.sources[filename] = {}
            self.sources[filename]['content'] = f.readlines()

    def get_source(self, url, fresh=False):
        """
        Gets a source from the specified url
        """
        from os.path import exists
        from urllib import request
        from urllib.error import URLError

        if not url.endswith('.md'):
            self.logger.error("Source must be a .md file")
            return

        filename = f"{self.source_dir}/{url.split('/')[2]}-{ url.split('/')[-1]}"
        if exists(filename):
            self.logger.warning("Source already exists: %s", filename)
            if not fresh:
                return self.read_source(filename)

        try:
            self.logger.info("Fetching source: %s", url)
            response = request.urlopen(url)
        except URLError as e:
            self.logger.error("Failed to fetch source: %s", e.reason)
            return

        raw_content = response.read().decode('utf-8').splitlines()
        content = [line for line in raw_content if line.strip()]

        with open(filename, 'w') as f:
            f.write('\n'.join(content))
            self.logger.info("Wrote source to file: %s", filename)

        self.sources[filename] = {}
        self.sources[filename]['content'] = content

    def fetch(self, fresh=False):
        """
        Fetches the latest resolver list from the sources
        """
        self._check_source_dir()
        for source, data in self.config['sources'].items():
            for url in data['urls']:
                self.get_source(url, fresh=fresh)
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
                        stamp = BaseStamp(line, logger=self.logger, ipv6=self.ipv6)
                    except Exception as e:
                        self.logger.error("Failed to process stamp, exception '%s', line: %s" % (e, line))
                        continue
                    self.logger.info("Found stamp: %s", stamp)
                    self.sources[source]['stamps'].append(stamp)
        for thread, exception in BaseStamp._threads:
            while not exception.empty():
                e = exception.get()
                self.logger.error("Exception in thread: %s", e)
            thread.join()

