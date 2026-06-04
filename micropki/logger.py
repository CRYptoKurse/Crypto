import logging
import sys
from datetime import datetime

def setup_logging(log_file=None):
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    if log_file:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setFormatter(formatter)
        root_logger.addHandler(fh)
    else:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(formatter)
        root_logger.addHandler(sh)
    return root_logger