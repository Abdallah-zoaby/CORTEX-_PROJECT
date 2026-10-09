
class BasePlugin:
    """Base class for all plugins"""
    
    name = "BasePlugin"
    version = "1.0"
    description = "Base plugin class"
    author = "Titanium Team"
    enabled = True
    supported_hooks = []
    
    async def pre_scan(self, scanner, config):
        pass
    
    async def post_scan(self, scanner, results):
        pass
    
    async def vulnerability_detected(self, scanner, vulnerability):
        pass
    
    async def request_sent(self, scanner, url, method, headers):
        pass
    
    async def response_received(self, scanner, url, response, headers):
        pass
