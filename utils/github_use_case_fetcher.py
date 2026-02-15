"""
GitHub Use Case Fetcher
Fetches use case YAML files from Splunk Security Content repository.
"""

import requests
import random
from typing import Dict, List, Optional


class GitHubUseCaseFetcher:
    """Fetches use cases from Splunk Security Content GitHub repository."""
    
    def __init__(self):
        self.base_url = "https://api.github.com"
        self.repo = "splunk/security_content"
        self.branch = "develop"
        self.detections_path = "detections"
    
    def get_all_use_case_files(self) -> List[Dict]:
        """Get list of all use case YAML files from GitHub."""
        all_files = []
        
        folders = ["application", "cloud", "endpoint", "network", "web"]
        
        for folder in folders:
            url = f"{self.base_url}/repos/{self.repo}/contents/{self.detections_path}/{folder}?ref={self.branch}"
            
            try:
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    files = response.json()
                    
                    for file in files:
                        if file["name"].endswith(".yml"):
                            all_files.append({
                                "path": file["path"],
                                "name": file["name"],
                                "download_url": file["download_url"],
                                "sha": file["sha"],
                                "folder": folder
                            })
            except:
                continue
        
        return all_files
    
    def select_random_diverse(self, all_files: List[Dict], count: int = 3, 
                              exclude_ids: List[str] = None) -> List[Dict]:
        """Select random use cases ensuring diversity across folders."""
        if exclude_ids is None:
            exclude_ids = []
        
        available = [f for f in all_files if f["sha"] not in exclude_ids]
        
        if len(available) == 0:
            return []
        
        if len(available) <= count:
            return available
        
        folders = list(set(f["folder"] for f in available))
        random.shuffle(folders)
        
        selected = []
        
        for folder in folders:
            if len(selected) >= count:
                break
            
            folder_files = [f for f in available if f["folder"] == folder]
            if folder_files:
                selected.append(random.choice(folder_files))
        
        while len(selected) < count:
            remaining = [f for f in available if f not in selected]
            if not remaining:
                break
            selected.append(random.choice(remaining))
        
        return selected[:count]
    
    def download_yaml_content(self, download_url: str) -> Optional[str]:
        """Download YAML content from URL."""
        try:
            response = requests.get(download_url, timeout=15)
            
            if response.status_code == 200:
                return response.text
            
            return None
        except:
            return None
