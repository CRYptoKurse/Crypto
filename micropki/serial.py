import os
import time
import struct
from cryptography.hazmat.primitives import serialization as crypto_serialization

def generate_unique_serial(db_path=None):
    """
    Генерирует 64-битный серийный номер, уникальный в рамках БД.
    Формат: старшие 32 бита = timestamp (секунды с 2020-01-01),
            младшие 32 бита = CSPRNG.
    Если db_path указан, проверяет уникальность и повторяет при коллизии.
    """
    epoch = int(time.mktime((2020, 1, 1, 0, 0, 0, 0, 0, 0)))  # 1577836800
    now = int(time.time())
    time_part = (now - epoch) & 0xFFFFFFFF  # ограничиваем 32 битами
    rand_part = int.from_bytes(os.urandom(4), 'big')  # 32 бита
    serial_int = (time_part << 32) | rand_part
    serial_hex = format(serial_int, 'x').upper()
    if db_path:
        # Проверяем уникальность (повторная проверка после вставки будет в БД)
        from micropki.database import get_certificate_by_serial
        while get_certificate_by_serial(db_path, serial_hex) is not None:
            rand_part = int.from_bytes(os.urandom(4), 'big')
            serial_int = (time_part << 32) | rand_part
            serial_hex = format(serial_int, 'x').upper()
    return serial_hex, serial_int