import requests
import json
from datetime import datetime

class GitHubDownloader:
    def __init__(self):
        self.base_url = "https://api.github.com"
        self.repo = "splunk/security_content"
        self.branch = "develop"
        self.detections_path = "detections"
        self.folders = ["application", "cloud", "endpoint", "network", "web"]
    
    def get_latest_commit(self):
        """Get latest commit SHA for the repo"""
        url = f"{self.base_url}/repos/{self.repo}/commits/{self.branch}"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()["sha"]
    
    def get_commit_diff(self, old_commit, new_commit):
        """Get files changed between two commits"""
        url = f"{self.base_url}/repos/{self.repo}/compare/{old_commit}...{new_commit}"
        response = requests.get(url)
        response.raise_for_status()
        
        data = response.json()
        changed_files = []
        
        for file in data.get("files", []):
            filename = file["filename"]
            if filename.startswith(self.detections_path) and filename.endswith(".yml"):
                changed_files.append({
                    "path": filename,
                    "status": file["status"]  # added, modified, removed
                })
        
        return changed_files
    
    def list_yaml_files(self, folder=None):
        """List all YAML files in detections folder(s)"""
        yaml_files = []
        
        folders_to_scan = [folder] if folder else self.folders
        
        for folder_name in folders_to_scan:
            path = f"{self.detections_path}/{folder_name}"
            url = f"{self.base_url}/repos/{self.repo}/contents/{path}?ref={self.branch}"
            
            response = requests.get(url)
            if response.status_code != 200:
                continue
                
            files = response.json()
            for file in files:
                if file["name"].endswith(".yml"):
                    yaml_files.append({
                        "path": file["path"],
                        "name": file["name"],
                        "sha": file["sha"],
                        "download_url": file["download_url"]
                    })
        
        return yaml_files
    
    def download_yaml_content(self, download_url):
        """Download raw YAML content"""
        response = requests.get(download_url)
        response.raise_for_status()
        return response.text
    
    def download_file_by_path(self, file_path):
        """Download a specific file by its path"""
        url = f"https://raw.githubusercontent.com/{self.repo}/{self.branch}/{file_path}"
        response = requests.get(url)
        response.raise_for_status()
        return response.text
