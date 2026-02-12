"""
URL Lookup Helper
Loads and queries vendor documentation URLs from Log_Definition_Links.csv
"""

import csv
from pathlib import Path
from typing import Optional, List, Dict


def load_vendor_doc_links(csv_path: str = "data/cim_knowledge/Log_Definition_Links.csv") -> Dict[str, List[str]]:
    """
    Load vendor documentation links from CSV.
    
    Returns:
        Dictionary mapping log source names to list of URLs
    """
    links_map = {}
    
    csv_file = Path(csv_path)
    if not csv_file.exists():
        return links_map
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            current_source = None
            
            for row in reader:
                log_source = row.get('Log Source', '').strip()
                link = row.get('Links', '').strip()
                
                # If log source is not empty, it's a new entry
                if log_source:
                    current_source = log_source
                    if current_source not in links_map:
                        links_map[current_source] = []
                
                # Add link if it exists
                if link and current_source:
                    links_map[current_source].append(link)
    
    except Exception as e:
        print(f"Error loading vendor doc links: {e}")
    
    return links_map


def lookup_doc_url(vendor: str, product: str, log_type: str) -> Optional[str]:
    """
    Look up documentation URL for a specific vendor/product/log type.
    
    Args:
        vendor: Vendor name (e.g., "Palo Alto")
        product: Product name (e.g., "Firewall")
        log_type: Log type (e.g., "Traffic")
        
    Returns:
        First matching URL or None
    """
    links_map = load_vendor_doc_links()
    
    # Try exact match first
    search_key = f"{vendor} {log_type}"
    if search_key in links_map and links_map[search_key]:
        return links_map[search_key][0]
    
    # Try partial matches
    search_terms = [
        f"{vendor} {product} {log_type}",
        f"{vendor} {log_type}",
        f"{product} {log_type}",
        vendor
    ]
    
    for term in search_terms:
        for source_name, urls in links_map.items():
            if term.lower() in source_name.lower() and urls:
                return urls[0]
    
    return None


def get_all_urls_for_source(vendor: str, product: str = "", log_type: str = "") -> List[str]:
    """
    Get all documentation URLs for a vendor/product.
    
    Returns:
        List of all matching URLs
    """
    links_map = load_vendor_doc_links()
    matching_urls = []
    
    search_terms = []
    if log_type:
        search_terms.append(f"{vendor} {log_type}")
    if product:
        search_terms.append(f"{vendor} {product}")
    search_terms.append(vendor)
    
    for term in search_terms:
        for source_name, urls in links_map.items():
            if term.lower() in source_name.lower():
                matching_urls.extend(urls)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in matching_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls
