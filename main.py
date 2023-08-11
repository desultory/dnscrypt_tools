#! /usr/bin/env python3

from stamps.processor import Processor
import logging

if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    processor = Processor(logger=logger)
    processor.generate_nftables_sets()
