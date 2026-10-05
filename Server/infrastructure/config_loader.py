import logging
from typing import Any

import yaml


logger = logging.getLogger(__name__)


class YamlConfigParser:
    def __init__(self, config_path="./data/config.yaml"):
        self.config_path = config_path
        self.config: dict[str, Any] = {}

    def load(self):
        self.config = {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as config_file:
                loaded_config = yaml.safe_load(config_file)
        except FileNotFoundError:
            logger.warning("Configuration file not found: %s", self.config_path)
            return
        except (OSError, yaml.YAMLError) as error:
            logger.warning("Could not load configuration file %s: %s", self.config_path, error)
            return

        if loaded_config is None:
            return
        if not isinstance(loaded_config, dict):
            logger.warning("Configuration file root must be a YAML mapping: %s", self.config_path)
            return
        self.config = loaded_config

    def get(self, key):
        return self.config.get(key)
