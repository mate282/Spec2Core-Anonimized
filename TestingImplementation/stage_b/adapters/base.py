from __future__ import annotations
import re
from abc import ABC, abstractmethod

class CoreAdapter(ABC):

    @abstractmethod
    def check_health(self, cfg: dict) -> dict:
        pass

    def lifecycle(self, action: str, target: str) -> bool:
        return False

    def check_data_plane_alive(self) -> bool:
        return False

    @abstractmethod
    def resolve_identity(self, cfg: dict, nf_type: str, fixture_role: str) -> str | None:
        pass

    def get_identity(self, cfg: dict, nf_type: str, fixture_role: str, refresh: bool=False) -> str | None:
        key = (nf_type.upper(), fixture_role)
        if not refresh and key in self._identity_mem_cache:
            return self._identity_mem_cache[key]
        if not refresh:
            disk_value = self._read_identities_file(cfg).get(fixture_role, {}).get('nf_instance_id')
            if disk_value:
                self._identity_mem_cache[key] = disk_value
                return disk_value
        value = self.resolve_identity(cfg, nf_type, fixture_role)
        if value:
            self._identity_mem_cache[key] = value
        return value

    @property
    def _identity_mem_cache(self) -> dict:
        if not hasattr(self, '_identity_mem_cache_store'):
            self._identity_mem_cache_store = {}
        return self._identity_mem_cache_store

    @staticmethod
    def _read_identities_file(cfg: dict) -> dict:
        path = (cfg.get('_paths') or {}).get('identities_file')
        if not path:
            return {}
        try:
            import yaml
            with open(path, encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            return data.get('services', {}) or {}
        except (OSError, Exception):
            return {}

    def provision_subscriber(self, cfg: dict) -> dict:
        return {'ok': False, 'amf1_instance_id': None, 'error': 'not implemented by this adapter'}

    def restore_uecm_binding(self, cfg: dict, amf1_id: str) -> bool:
        return False

    def restore_amf_non3gpp_binding(self, cfg: dict, amf1_id: str) -> bool:
        return False

    def restore_smf_registration(self, cfg: dict, owner_id: str) -> bool:
        return False

    def search_logs(self, target: str, pattern: str, tail: int | None=None) -> str | None:
        raw = self.read_logs(target, tail)
        if not raw:
            return None
        matches = re.findall(pattern, raw)
        return matches[-1] if matches else None

    def search_db(self, identifier: str) -> str | None:
        return None

    def discover_service_base_path(self, cfg: dict, scope: str, producer_nf_type: str, fixture_role: str) -> str | None:
        return None

    def read_logs(self, target: str, tail: int | None=None) -> str:
        return ''

    def read_db_state(self, identifier: str) -> dict | list | str | None:
        return None

    def get_structured_doc(self, collection: str, key_field: str, key_value: str) -> dict | None:
        return None

    def list_db_collections(self) -> list[str]:
        return []

class MongoEvidenceMixin:

    def _open_mongo(self, cfg: dict):
        from pymongo import MongoClient
        m = cfg['services']['mongodb']
        client = MongoClient(f'mongodb://{m['host']}:{m['port']}', serverSelectionTimeoutMS=3000)
        client.admin.command('ping')
        return client[m['database']]

    def mongo_get_structured_doc(self, cfg: dict, collection: str, key_field: str, key_value: str) -> dict | None:
        try:
            db = self._open_mongo(cfg)
            return db[collection].find_one({key_field: key_value}, {'_id': 0})
        except Exception:
            return None

    def mongo_list_collections(self, cfg: dict) -> list[str]:
        try:
            db = self._open_mongo(cfg)
            return sorted(db.list_collection_names())
        except Exception:
            return []

    def mongo_read_db_state(self, cfg: dict, identifier: str) -> list:
        import json as _json
        try:
            db = self._open_mongo(cfg)
        except Exception:
            return []
        hits = []
        try:
            for coll_name in db.list_collection_names():
                for doc in db[coll_name].find({}, {'_id': 0}):
                    try:
                        text = _json.dumps(doc, default=str)
                    except Exception:
                        continue
                    if identifier in text:
                        hits.append({'collection': coll_name, 'document': doc})
        except Exception:
            pass
        return hits

class RelationalEvidenceMixin:

    def _open_sql(self, cfg: dict):
        s = cfg['services']['sql_db']
        driver = s.get('driver', 'postgresql')
        if driver == 'postgresql':
            import psycopg2
            return psycopg2.connect(host=s['host'], port=s['port'], dbname=s['database'], user=s.get('user'), password=s.get('password'))
        if driver == 'mysql':
            import mysql.connector
            return mysql.connector.connect(host=s['host'], port=s['port'], database=s['database'], user=s.get('user'), password=s.get('password'))
        raise ValueError(f"Unsupported sql_db driver: {driver!r} (expected 'postgresql' or 'mysql')")

    def sql_get_structured_doc(self, cfg: dict, table: str, key_field: str, key_value: str) -> dict | None:
        try:
            conn = self._open_sql(cfg)
        except Exception:
            return None
        try:
            cur = conn.cursor()
            cur.execute(f'SELECT * FROM "{table}" WHERE "{key_field}" = %s', (key_value,))
            row = cur.fetchone()
            if row is None:
                return None
            columns = [d[0] for d in cur.description]
            return dict(zip(columns, row))
        except Exception:
            return None
        finally:
            conn.close()

    def sql_read_db_state(self, cfg: dict, identifier: str) -> list:
        try:
            conn = self._open_sql(cfg)
        except Exception:
            return []
        hits: list = []
        try:
            cur = conn.cursor()
            cur.execute("SELECT table_name, column_name FROM information_schema.columns WHERE data_type IN ('character varying', 'text', 'varchar', 'char', 'longtext')")
            text_columns = cur.fetchall()
            for table_name, column_name in text_columns:
                try:
                    scan_cur = conn.cursor()
                    scan_cur.execute(f'SELECT * FROM "{table_name}" WHERE CAST("{column_name}" AS CHAR) LIKE %s', (f'%{identifier}%',))
                    rows = scan_cur.fetchall()
                    if rows:
                        cols = [d[0] for d in scan_cur.description]
                        for row in rows:
                            hits.append({'table': table_name, 'row': dict(zip(cols, row))})
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            conn.close()
        return hits
