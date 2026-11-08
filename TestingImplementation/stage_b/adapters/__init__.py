from __future__ import annotations
from .base import CoreAdapter, MongoEvidenceMixin, RelationalEvidenceMixin
from .free5gc import Free5GCAdapter
from .open5gs import Open5GSAdapter
_ADAPTERS: dict[str, type[CoreAdapter]] = {'free5gc': Free5GCAdapter, 'open5gs': Open5GSAdapter}

def get_adapter(cfg: dict) -> CoreAdapter:
    name = cfg.get('core_adapter', 'free5gc')
    try:
        adapter_cls = _ADAPTERS[name]
    except KeyError:
        raise ValueError(f"Unknown core_adapter '{name}' in lab config — registered adapters: {sorted(_ADAPTERS)}")
    return adapter_cls(cfg)
__all__ = ['CoreAdapter', 'MongoEvidenceMixin', 'RelationalEvidenceMixin', 'Free5GCAdapter', 'Open5GSAdapter', 'get_adapter']
