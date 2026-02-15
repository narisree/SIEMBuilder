"""
Use Case Cache Manager
Handles persistent storage and retrieval of downloaded Splunk use cases.
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class UseCaseCache:
    """Manages persistent cache for downloaded use cases."""
    
    def __init__(self, cache_dir: str = "cache"):
        """Initialize cache manager."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        self.db_path = self.cache_dir / "use_cases.db"
        self.json_backup_path = self.cache_dir / "use_cases_backup.json"
        self.download_history_path = self.cache_dir / "download_history.json"
        
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS use_cases (
                use_case_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                data_models TEXT,
                mapped_sources TEXT,
                mitre_technique TEXT,
                mitre_tactics TEXT,
                spl_query TEXT,
                l1_what_it_detects TEXT,
                l1_validation_steps TEXT,
                raw_yaml TEXT,
                cached_at TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def get_cached_count(self) -> int:
        """Get count of cached use cases."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM use_cases")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def get_downloaded_ids(self) -> List[str]:
        """Get list of all downloaded use case IDs."""
        if not self.download_history_path.exists():
            return []
        
        try:
            with open(self.download_history_path, 'r', encoding='utf-8') as f:
                history = json.load(f)
                return history.get("downloaded_ids", [])
        except:
            return []
    
    def add_to_cache(self, use_case: Dict):
        """Add a use case to cache."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO use_cases 
            (use_case_id, name, description, data_models, mapped_sources, 
             mitre_technique, mitre_tactics, spl_query, l1_what_it_detects,
             l1_validation_steps, raw_yaml, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            use_case.get("detection_id", ""),
            use_case.get("name", ""),
            use_case.get("description", ""),
            json.dumps(use_case.get("data_models", [])),
            json.dumps(use_case.get("mapped_sources", [])),
            use_case.get("mitre_technique", ""),
            use_case.get("mitre_tactics", ""),
            use_case.get("spl_query", ""),
            use_case.get("L1_What_It_Detects", ""),
            json.dumps(use_case.get("L1_Validation_Steps", [])),
            use_case.get("raw_yaml", ""),
            datetime.utcnow().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        self._update_download_history(use_case.get("detection_id", ""))
    
    def _update_download_history(self, use_case_id: str):
        """Update download history."""
        history = {"downloaded_ids": [], "download_sessions": []}
        
        if self.download_history_path.exists():
            with open(self.download_history_path, 'r', encoding='utf-8') as f:
                history = json.load(f)
        
        if use_case_id not in history["downloaded_ids"]:
            history["downloaded_ids"].append(use_case_id)
        
        with open(self.download_history_path, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2)
    
    def get_all_cached(self) -> List[Dict]:
        """Get all cached use cases."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM use_cases")
        rows = cursor.fetchall()
        conn.close()
        
        use_cases = []
        for row in rows:
            use_cases.append({
                "detection_id": row[0],
                "name": row[1],
                "description": row[2],
                "data_models": json.loads(row[3]) if row[3] else [],
                "mapped_sources": json.loads(row[4]) if row[4] else [],
                "mitre_technique": row[5],
                "mitre_tactics": row[6],
                "spl_query": row[7],
                "L1_What_It_Detects": row[8],
                "L1_Validation_Steps": json.loads(row[9]) if row[9] else [],
                "raw_yaml": row[10],
                "cached_at": row[11]
            })
        
        return use_cases
    
    def get_for_source(self, source_slug: str) -> List[Dict]:
        """Get cached use cases for a specific log source."""
        all_cases = self.get_all_cached()
        
        filtered = []
        for case in all_cases:
            if source_slug in case.get("mapped_sources", []):
                filtered.append(case)
        
        return filtered
    
    def export_to_json(self):
        """Export cache to JSON backup."""
        all_cases = self.get_all_cached()
        
        with open(self.json_backup_path, 'w', encoding='utf-8') as f:
            json.dump(all_cases, f, indent=2)
    
    def import_from_json(self):
        """Import cache from JSON backup."""
        if not self.json_backup_path.exists():
            return
        
        with open(self.json_backup_path, 'r', encoding='utf-8') as f:
            use_cases = json.load(f)
        
        for case in use_cases:
            self.add_to_cache(case)
