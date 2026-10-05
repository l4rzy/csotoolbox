import ipaddress
import logging
import threading
from pathlib import Path

import maxminddb

logger = logging.getLogger(__name__)


class MaxMindGeoIPReader:
    def __init__(self, db_path: str):
        self._db_path = str(Path(db_path).resolve())
        self._lock = threading.Lock()
        self._reader = None
        self._open()

    def _open(self):
        with self._lock:
            try:
                self._reader = maxminddb.open_database(self._db_path)
                logger.info(f"Opened MaxMind DB: {self._db_path}")
            except Exception as e:
                logger.error(f"Failed to open MaxMind DB {self._db_path}: {e}")
                self._reader = None

    def lookup(self, ip: str) -> dict | None:
        reader = self._reader
        if reader is None:
            return None
        try:
            return reader.get(ip)
        except Exception as e:
            logger.warning(f"MaxMind lookup failed for {ip}: {e}")
            return None

    def reload(self):
        old = self._reader
        self._open()
        if old is not None:
            try:
                old.close()
            except Exception:
                pass

    def close(self):
        with self._lock:
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception:
                    pass
                self._reader = None


_MMDB_TO_GEOIP = {
    "ip_country_code": lambda record: record.get("country", {}).get("iso_code"),
    "ip_country_name": lambda record: record.get("country", {}).get("names", {}).get("en"),
    "ip_state_name": lambda record: _subdiv_name(record),
    "ip_city": lambda record: record.get("city", {}).get("names", {}).get("en"),
    "ip_postcode": lambda record: record.get("postal", {}).get("code"),
    "ip_geolocation": lambda record: _geolocation(record),
    "ip_geoname_id": lambda record: str(record.get("city", {}).get("geoname_id")) if record.get("city", {}).get("geoname_id") is not None else None,
    "ip_location_accuracy_km": lambda record: str(record.get("location", {}).get("accuracy_radius")) if record.get("location", {}).get("accuracy_radius") is not None else None,
    "ip_time_zone": lambda record: record.get("location", {}).get("time_zone"),
    "ip_continent_code": lambda record: record.get("continent", {}).get("code"),
    "ip_continent_name": lambda record: record.get("continent", {}).get("names", {}).get("en"),
    "ip_range_from": lambda record: _range_from(record),
    "ip_range_to": lambda record: _range_to(record),
}


def _subdiv_name(record: dict) -> str | None:
    subs = record.get("subdivisions")
    if subs and isinstance(subs, list) and len(subs) > 0:
        return subs[0].get("names", {}).get("en")
    return None


def _geolocation(record: dict) -> str | None:
    loc = record.get("location")
    if loc and "latitude" in loc and "longitude" in loc:
        return f"{loc['latitude']},{loc['longitude']}"
    return None


def _range_from(record: dict) -> str | None:
    net = record.get("traits", {}).get("network")
    if net:
        try:
            n = ipaddress.ip_network(net, strict=False)
            return str(n[0])
        except Exception:
            pass
    return None


def _range_to(record: dict) -> str | None:
    net = record.get("traits", {}).get("network")
    if net:
        try:
            n = ipaddress.ip_network(net, strict=False)
            return str(n[-1])
        except Exception:
            pass
    return None


def build_geoip_from_mmdb(ip: str, reader: MaxMindGeoIPReader) -> dict:
    record = reader.lookup(ip)
    if not record:
        return {}

    geoip = {}
    for field, extractor in _MMDB_TO_GEOIP.items():
        try:
            val = extractor(record)
            if val is not None and (not isinstance(val, str) or val.strip()):
                geoip[field] = val
        except Exception:
            continue

    geoip["datasource_name"] = "maxmind_geolite2_local"
    return geoip
