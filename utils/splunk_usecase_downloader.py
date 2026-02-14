"""
Use Case Downloader
Downloads and processes Splunk security content detections using Claude API.
"""

import json
import yaml
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Callable
from utils.github_downloader import GitHubDownloader
from utils.claude_client import ClaudeClient

class UseCaseDownloader:
    """Downloads and processes Splunk security content use cases."""
    
    def __init__(self, claude_api_key: str, kb_path: str = "kb"):
        self.github = GitHubDownloader()
        self.claude = ClaudeClient(claude_api_key)
        self.kb_path = Path(kb_path)
        self.metadata_file = self.kb_path / "splunk_sync_metadata.json"
    
    def check_for_updates(self) -> Dict:
        """Check if updates are available from GitHub."""
        metadata = self._load_sync_metadata()
        
        try:
            latest_commit = self.github.get_latest_commit()
        except Exception as e:
            return {"needs_update": False, "error": str(e)}
        
        if not metadata:
            return {"needs_update": True, "is_first_sync": True, "files_to_download": None}
        
        if metadata["last_sync_commit"] == latest_commit:
            return {"needs_update": False, "is_first_sync": False}
        
        try:
            changed_files = self.github.get_commit_diff(metadata["last_sync_commit"], latest_commit)
        except Exception:
            return {"needs_update": True, "is_first_sync": True, "files_to_download": None}
        
        return {
            "needs_update": True,
            "is_first_sync": False,
            "files_to_download": changed_files,
            "new_count": sum(1 for f in changed_files if f["status"] == "added"),
            "modified_count": sum(1 for f in changed_files if f["status"] == "modified"),
            "deleted_count": sum(1 for f in changed_files if f["status"] == "removed")
        }
    
    def download_and_process(self, progress_callback: Optional[Callable] = None) -> Dict:
        """Download and process use cases."""
        update_info = self.check_for_updates()
        
        if not update_info["needs_update"]:
            return {"status": "up_to_date", "message": "Already up to date"}
        
        if "error" in update_info:
            return {"status": "error", "message": update_info["error"]}
        
        if update_info["is_first_sync"]:
            return self._full_download(progress_callback)
        else:
            return self._incremental_download(update_info, progress_callback)
    
    def _full_download(self, progress_callback: Optional[Callable] = None) -> Dict:
        """Perform full download of all use cases."""
        try:
            all_yaml_files = self.github.list_yaml_files()
            total_files = len(all_yaml_files)
            
            if progress_callback:
                progress_callback(0, total_files, "Starting download...")
            
            yaml_contents = []
            
            for idx, file_info in enumerate(all_yaml_files):
                try:
                    yaml_content = self.github.download_yaml_content(file_info["download_url"])
                    yaml_contents.append({
                        "content": yaml_content,
                        "path": file_info["path"],
                        "sha": file_info["sha"]
                    })
                    
                    if progress_callback and (idx + 1) % 20 == 0:
                        progress_callback(idx + 1, total_files, f"Downloaded {idx + 1}/{total_files} files...")
                    
                    time.sleep(0.05)
                    
                except Exception:
                    continue
            
            if progress_callback:
                progress_callback(total_files, total_files, "Processing with Claude...")
            
            mapped_use_cases = self._process_with_claude(yaml_contents, progress_callback)
            
            self._save_use_cases(mapped_use_cases)
            
            latest_commit = self.github.get_latest_commit()
            metadata = {
                "last_sync_commit": latest_commit,
                "last_sync_timestamp": datetime.utcnow().isoformat() + "Z",
                "total_detections": len(yaml_contents),
                "file_hashes": {item["path"]: item["sha"] for item in yaml_contents}
            }
            self._save_sync_metadata(metadata)
            
            return {
                "status": "success",
                "total_processed": len(yaml_contents),
                "is_first_sync": True
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _incremental_download(self, update_info: Dict, progress_callback: Optional[Callable] = None) -> Dict:
        """Perform incremental download of changed files."""
        try:
            files_to_process = [f for f in update_info["files_to_download"] if f["status"] != "removed"]
            total_files = len(files_to_process)
            
            if progress_callback:
                progress_callback(0, total_files, "Downloading updates...")
            
            yaml_contents = []
            
            for idx, file_info in enumerate(files_to_process):
                try:
                    yaml_content = self.github.download_file_by_path(file_info["path"])
                    yaml_contents.append({
                        "content": yaml_content,
                        "path": file_info["path"],
                        "status": file_info["status"]
                    })
                    
                    if progress_callback:
                        progress_callback(idx + 1, total_files, f"Processed {idx + 1}/{total_files} files...")
                    
                    time.sleep(0.05)
                    
                except Exception:
                    continue
            
            if yaml_contents:
                mapped_use_cases = self._process_with_claude(yaml_contents, progress_callback)
                self._save_use_cases(mapped_use_cases, is_update=True)
            
            latest_commit = self.github.get_latest_commit()
            metadata = self._load_sync_metadata()
            metadata["last_sync_commit"] = latest_commit
            metadata["last_sync_timestamp"] = datetime.utcnow().isoformat() + "Z"
            self._save_sync_metadata(metadata)
            
            return {
                "status": "success",
                "new_count": update_info["new_count"],
                "modified_count": update_info["modified_count"],
                "is_first_sync": False
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _process_with_claude(self, yaml_contents: List[Dict], progress_callback: Optional[Callable] = None) -> List[Dict]:
        """Process YAML contents with Claude in batches."""
        all_mapped = []
        batch_size = 3
        
        for i in range(0, len(yaml_contents), batch_size):
            batch = yaml_contents[i:i+batch_size]
            
            try:
                result = self._claude_process_batch(batch)
                all_mapped.extend(result)
                
                if progress_callback and len(yaml_contents) > 10:
                    progress = min(i + batch_size, len(yaml_contents))
                    progress_callback(progress, len(yaml_contents), f"Claude processing: {progress}/{len(yaml_contents)}")
                
                time.sleep(1)
                
            except Exception:
                continue
        
        return all_mapped
    
    def _claude_process_batch(self, yaml_batch: List[Dict]) -> List[Dict]:
        """Process a batch of YAMLs with Claude."""
        log_sources = [
            "palo_alto", "windows_events", "linux", "azure_ad", "cisco_asa",
            "checkpoint", "crowdstrike_edr", "o365", "proofpoint", "zscaler_proxy"
        ]
        
        system_prompt = """You are a SIEM integration specialist expert in Splunk detection mappings.

Your task: Analyze Splunk detection YAMLs and map them to appropriate log sources, then transform to the required format.

Available log sources (use exact slugs):
- palo_alto: Palo Alto Firewall
- windows_events: Windows Events
- linux: Linux systems
- azure_ad: Azure AD / Microsoft Entra ID
- cisco_asa: Cisco ASA Firewall
- checkpoint: Check Point Firewall  
- crowdstrike_edr: CrowdStrike EDR
- o365: Office 365 / Microsoft 365
- proofpoint: Proofpoint Email Security
- zscaler_proxy: Zscaler Proxy

Mapping rules:
1. PRIMARY: Use 'data_source' field if present - match keywords to log sources
2. FALLBACK: Use 'datamodel' from SPL search field:
   - Network_Traffic → palo_alto, cisco_asa, checkpoint
   - Endpoint → windows_events, crowdstrike_edr, linux
   - Web → zscaler_proxy
   - Authentication → azure_ad, windows_events, o365
   - Email → proofpoint, o365
3. SPECIAL: Suricata + Web datamodel → zscaler_proxy
4. Analyze SPL 'search' field for sourcetype clues

Output format for each detection (JSON array):
{
  "detection_id": "from id field",
  "name": "from name field",
  "mapped_sources": ["source_slug1", "source_slug2"],
  "mitre_technique": "from tags.mitre_attack_id",
  "mitre_tactics": "from tags (tactic names)",
  "description": "from description field",
  "spl_query": "from search field",
  "L1_What_It_Detects": "2-3 sentence explanation of what this detection identifies, written for L1 analysts. Focus on the threat behavior and why it matters.",
  "L1_Validation_Steps": [
    "Step 1: Specific action to verify the alert (e.g., 'Check if the source IP belongs to your organization')",
    "Step 2: Another validation step",
    "Step 3: Another validation step",
    "Step 4: Another validation step",
    "Step 5: Another validation step",
    "Step 6: Final step (e.g., 'If still suspicious, escalate to L2')"
  ]
}

CRITICAL L1 Guidance Requirements:
- L1_What_It_Detects: Must be clear, concise, non-technical explanation suitable for junior analysts
- L1_Validation_Steps: Must provide 5-6 ACTIONABLE steps that an L1 analyst can perform
- Steps should be specific to the detection, not generic
- Include checks like: verify source/destination, check user context, review timing, check threat intelligence, confirm with asset owner, escalation criteria

Return ONLY valid JSON array. No markdown, no explanations."""

        yaml_texts = []
        for item in yaml_batch:
            yaml_texts.append(f"---\nFile: {item['path']}\n{item['content']}\n")
        
        combined_yaml = "\n".join(yaml_texts)
        
        prompt = f"""Analyze these {len(yaml_batch)} detection(s) and return JSON array:

{combined_yaml}

Remember: Return ONLY the JSON array, no markdown formatting.
Ensure each detection has L1_What_It_Detects as a string and L1_Validation_Steps as an array of 5-6 specific steps."""

        messages = [{"role": "user", "content": prompt}]
        
        response = self.claude.client.messages.create(
            model=self.claude.model,
            max_tokens=8000,
            system=system_prompt,
            messages=messages
        )
        
        response_text = response.content[0].text.strip()
        
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        try:
            parsed = json.loads(response_text)
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return []
    
    def _save_use_cases(self, mapped_use_cases: List[Dict], is_update: bool = False):
        """Save use cases to respective log source files."""
        use_cases_by_source = {}
        
        for use_case in mapped_use_cases:
            for source in use_case.get("mapped_sources", []):
                if source not in use_cases_by_source:
                    use_cases_by_source[source] = []
                use_cases_by_source[source].append(use_case)
        
        for source_slug, cases in use_cases_by_source.items():
            usecase_file = self.kb_path / f"{source_slug}_usecases.json"
            
            if is_update and usecase_file.exists():
                with open(usecase_file, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
                
                existing_ids = {uc.get("detection_id") for uc in existing}
                
                for case in cases:
                    case_id = case.get("detection_id")
                    existing[:] = [uc for uc in existing if uc.get("detection_id") != case_id]
                    existing.append(case)
                
                with open(usecase_file, 'w', encoding='utf-8') as f:
                    json.dump(existing, f, indent=2)
            else:
                with open(usecase_file, 'w', encoding='utf-8') as f:
                    json.dump(cases, f, indent=2)
    
    def _load_sync_metadata(self) -> Optional[Dict]:
        """Load sync metadata."""
        if not self.metadata_file.exists():
            return None
        
        try:
            with open(self.metadata_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    def _save_sync_metadata(self, metadata: Dict):
        """Save sync metadata."""
        with open(self.metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
