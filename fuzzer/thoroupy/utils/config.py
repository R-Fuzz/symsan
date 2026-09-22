from yaml import safe_load

from typing import Dict, List
import os

class Config:
    def __init__(self, path: str| Dict = 'config.yaml') -> None:
        self._config: Dict = dict()
        if isinstance(path, (str, os.PathLike, bytes)):
            self._load(path)
        else:
            self._config = path

    def _load(self, path:str):
        with open(path, "r") as f:
            self._config = safe_load(f)
    
    def get(self, key, default):
        if key in self._config:
            if type(self._config[key]) is dict:
                return DotProxy(self._config, key)
            else:
                return self._config[key]
        else:
            return default
    
    def __getattr__(self, key: str) -> "DotProxy | str | int | float | bool | List":
        if key in self._config:
            if type(self._config[key]) is dict:
                return DotProxy(self._config, key)
            else:
                return self._config[key]
        else:
            raise AttributeError(f"Config has no attribute {key}")
    
    def __contains__(self, keyword):
        return keyword in self._config
        
class DotProxy:
    def __init__(self, config, key) -> None:
        self._current:Dict = config[key]
    
    def __getattr__(self, key: str):
        if key in self._current:
            if type(self._current[key]) is dict:
                return DotProxy(self._current, key)
            else:
                return self._current[key]
        else:
            raise AttributeError(f"Config has no attribute {key}")

    def items(self):
        return self._current.items()
    
    def __dict__(self):
        return self._current

    def __contains__(self, keyword):
        return keyword in self._current

    def __iter__(self):
        if isinstance(self._current, dict):
            return iter(self.items())
        else:
            return self.__iter__()