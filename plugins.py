import os
import sys
import importlib.util
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import tempfile

logger = logging.getLogger(__name__)

class Plugin:
    def __init__(self, name: str, description: str, version: str):
        self.name = name
        self.description = description
        self.version = version
        self.enabled = True
        self.config = {}
        self.last_run = None

    def execute(self, *args, **kwargs) -> bool:
        raise NotImplementedError("Plugin must implement execute method")

    def get_config(self) -> Dict[str, Any]:
        return self.config

    def set_config(self, config: Dict[str, Any]):
        self.config = config

class FilePlugin(Plugin):
    def __init__(self, name: str, description: str, version: str, file_path: str):
        super().__init__(name, description, version)
        self.file_path = file_path

    def execute(self, target_clients: Optional[List[str]] = None) -> bool:
        try:
            if not os.path.exists(self.file_path):
                logger.error(f"File not found: {self.file_path}")
                return False
            self.last_run = datetime.now()
            return True
        except Exception as e:
            logger.error(f"Error executing file plugin {self.name}: {e}")
            return False

class ScriptPlugin(Plugin):
    def __init__(self, name: str, description: str, version: str, script: str):
        super().__init__(name, description, version)
        self.script = script

    def execute(self, target_clients: Optional[List[str]] = None) -> bool:
        try:
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                f.write(self.script)
                script_path = f.name

            self.last_run = datetime.now()
            return True
        except Exception as e:
            logger.error(f"Error executing script plugin {self.name}: {e}")
            return False
        finally:
            try:
                os.unlink(script_path)
            except:
                pass

class PluginManager:
    def __init__(self):
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_dir = "plugins"
        self.config_file = "plugin_config.json"
        self.load_config()

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    for plugin_name, plugin_config in config.items():
                        if plugin_name in self.plugins:
                            self.plugins[plugin_name].set_config(plugin_config)
        except Exception as e:
            logger.error(f"Error loading plugin config: {e}")

    def save_config(self):
        try:
            config = {name: plugin.get_config() for name, plugin in self.plugins.items()}
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving plugin config: {e}")

    def load_plugins(self):
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith('.py'):
                try:
                    module_name = filename[:-3]
                    spec = importlib.util.spec_from_file_location(
                        module_name, os.path.join(self.plugin_dir, filename)
                    )
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        if hasattr(module, 'register_plugin'):
                            plugin = module.register_plugin()
                            self.plugins[plugin.name] = plugin
                except Exception as e:
                    logger.error(f"Error loading plugin {filename}: {e}")

    def get_plugin(self, name: str) -> Optional[Plugin]:
        return self.plugins.get(name)

    def get_all_plugins(self) -> Dict[str, Plugin]:
        return self.plugins.copy()

    def add_plugin(self, plugin: Plugin):
        self.plugins[plugin.name] = plugin
        self.save_config()

    def remove_plugin(self, name: str):
        if name in self.plugins:
            del self.plugins[name]
            self.save_config()

    def execute_plugin(self, name: str, *args, **kwargs) -> bool:
        plugin = self.get_plugin(name)
        if plugin and plugin.enabled:
            return plugin.execute(*args, **kwargs)
        return False

    def create_file_plugin(self, name: str, description: str, version: str, file_path: str) -> FilePlugin:
        plugin = FilePlugin(name, description, version, file_path)
        self.add_plugin(plugin)
        return plugin

    def create_script_plugin(self, name: str, description: str, version: str, script: str) -> ScriptPlugin:
        plugin = ScriptPlugin(name, description, version, script)
        self.add_plugin(plugin)
        return plugin 