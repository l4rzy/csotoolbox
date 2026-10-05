import asyncio
import csv
import logging

import ipaddress


logger = logging.getLogger(__name__)


class IPDBInfo:
    def __init__(self, data_file):
        self.db = None
        self.data_file = data_file
        self.disabled = False

    async def query(self, ip):
        if self.db is None:
            try:

                def _read_db():
                    with open(self.data_file, "rt") as file:
                        reader = csv.reader(file, delimiter=",")
                        return list(reader)

                self.db = await asyncio.to_thread(_read_db)
            except Exception as e:
                logger.warning(f"[ipdb] error: {e}")
                self.disabled = True

        res = {
            "found": False,
            "ip": ip,
            "cidr": "",
            "usage": "",
            "location": "",
            "comment": "",
        }

        if self.disabled:
            return res

        try:
            target_ip = ipaddress.IPv4Address(ip)
        except Exception:
            return res

        best_match = None
        best_prefixlen = -1

        for row in self.db:
            try:
                net = ipaddress.IPv4Network(row[0])
                if target_ip in net:
                    if net.prefixlen > best_prefixlen:
                        best_prefixlen = net.prefixlen
                        best_match = row
            except Exception:
                continue

        if best_match is not None:
            res = {
                "found": True,
                "ip": ip,
                "cidr": best_match[0],
                "usage": best_match[1],
                "location": best_match[2],
                "comment": best_match[3],
            }

        return res
