from infrastructure.models import ServiceType, TunnelOptions, ServiceResult
from services.base import TunnelService


class IpdbService(TunnelService):
    def __init__(self, ipdb_info):
        self._ipdb = ipdb_info

    @property
    def service_type(self) -> ServiceType:
        return ServiceType.IPDB

    async def handle(self, payload: str, options: TunnelOptions) -> ServiceResult:
        res_dict = await self._ipdb.query(payload)
        return ServiceResult(payload=res_dict, error=None)
