
import logging
from pathlib import Path
from .base import BasePlugin
from .builtins import (
    SQLiPlugin, XSSPlugin, LFIPlugin, 
    HeaderSecurityPlugin, SensitiveDataPlugin, IDORPlugin
)
from ..config import CONFIG

logger = logging.getLogger("TitaniumScanner")

class PluginManager:
    """Dynamic plugin system"""
    
    def __init__(self):
        self.plugins = {}
        self.hooks = {
            'pre_scan': [],
            'post_scan': [],
            'vulnerability_detected': [],
            'request_sent': [],
            'response_received': [],
        }
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from directory"""
        plugin_dir = Path(CONFIG['PLUGIN_DIR'])
        if not plugin_dir.exists():
            plugin_dir.mkdir(parents=True, exist_ok=True)
        
        # Load built-in plugins
        self._load_builtin_plugins()
        
        # Load external plugins (placeholder logic)
        for plugin_file in plugin_dir.glob("*.py"):
            try:
                # self._load_plugin(plugin_file) # Implementation skipped for now
                pass
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file}: {e}")
    
    def _load_builtin_plugins(self):
        """Load built-in plugins"""
        builtin_plugins = [
            SQLiPlugin(),
            XSSPlugin(),
            LFIPlugin(),
            HeaderSecurityPlugin(),
            SensitiveDataPlugin(),
            IDORPlugin(),
        ]
        
        for plugin in builtin_plugins:
            self.register_plugin(plugin)
    
    def register_plugin(self, plugin):
        """Register a plugin"""
        self.plugins[plugin.name] = plugin
        
        # Register hooks
        for hook_name in plugin.supported_hooks:
            # We assume the hook method exists on the plugin instance
            if hasattr(plugin, hook_name):
                self.hooks[hook_name].append(getattr(plugin, hook_name))
        
        logger.info(f"✅ Plugin loaded: {plugin.name} v{plugin.version}")
    
    async def execute_hook(self, hook_name: str, *args, **kwargs):
        """Execute all plugins for a hook"""
        results = []
        for hook_func in self.hooks.get(hook_name, []):
            try:
                result = await hook_func(*args, **kwargs)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Plugin hook {hook_name} failed: {e}")
        return results
