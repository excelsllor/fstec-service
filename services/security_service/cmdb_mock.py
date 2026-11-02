"""Мок-CMDB (инвентарь Заказчика) по структуре Приложения 8 (phase1_appendix8.md),
реализует тот же протокол InventoryClient, что и RestCMDB (security_service.cmdb).

В dev-контуре реальная CMDB недоступна → используется этот мок.
"""
from security_service.cmdb import InventoryItem

MOCK_INVENTORY: list[InventoryItem] = [
    InventoryItem("Log4j", "Apache", "2.15.0", "библиотека", "srv-app-01",
                  cpe="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"),
    InventoryItem("OpenSSL", "OpenSSL", "1.1.1k", "библиотека", "srv-web-02",
                  cpe="cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*:*"),
    InventoryItem("Microsoft Edge", "Microsoft", "108.0.1462.42", "браузер", "ws-employee-01",
                  cpe="cpe:2.3:a:microsoft:edge:108.0.1462.42:*:*:*:*:*:*:*:*"),
]


class MockCMDB:
    """Подстрочный поиск по имени (регистронезависимо); find_many — тот же контракт, что у RestCMDB."""

    def __init__(self, items: list[InventoryItem] | None = None):
        self.items = items or MOCK_INVENTORY

    def find_software(self, software_name: str) -> InventoryItem | None:
        if not software_name:
            return None
        s = software_name.strip().lower()
        for it in self.items:
            n = it.name.lower()
            v = it.vendor.lower()
            if n in s or s in n or (v in s and s.split()[-1] == n):
                return it
        return None

    async def find_many(self, product: str) -> list[InventoryItem]:
        found = self.find_software(product)
        return [found] if found else []