# serial.py
import os
import time
from datetime import datetime, timezone

def generate_unique_serial(db_path=None):
    """
    Генерирует 64-битный серийный номер, уникальный в рамках БД.
    Формат: старшие 32 бита = timestamp (секунды с 2020-01-01 UTC),
            младшие 32 бита = CSPRNG.
    """
    epoch = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    now = time.time()
    time_part = int((now - epoch)) & 0xFFFFFFFF
    rand_part = int.from_bytes(os.urandom(4), 'big')
    serial_int = (time_part << 32) | rand_part
    serial_hex = format(serial_int, 'x').upper()
    if db_path:
        from micropki.database import get_certificate_by_serial
        while get_certificate_by_serial(db_path, serial_hex) is not None:
            rand_part = int.from_bytes(os.urandom(4), 'big')
            serial_int = (time_part << 32) | rand_part
            serial_hex = format(serial_int, 'x').upper()
    return serial_hex, serial_int