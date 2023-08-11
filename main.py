#! /usr/bin/env python3

from stamps.processor import Processor
import logging

if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    processor = Processor(logger=logger)

    print(processor.get_all_ips())
