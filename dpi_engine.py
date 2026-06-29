import re
import urllib.parse

class DPIEngine:
    def __init__(self):
        # Common attack signatures using Regex
        self.signatures = {
            "SQL Injection": [
                r"(?i)\bSELECT\b.*\bFROM\b",
                r"(?i)\bUNION\b.*\bSELECT\b",
                r"(?i)\bDROP\b\s+\bTABLE\b",
                r"(?i)\bOR\b\s+\d+\s*=\s*\d+",
                r"(?i)'\s*OR\s*'1'\s*=\s*'1"
            ],
            "Web Test": [
                r"(?i)(example\.com|apple\.com|google\.com)"
            ],
            "XSS Attack": [
                r"(?i)<\s*script.*?>",
                r"(?i)javascript:",
                r"(?i)onerror\s*=",
                r"(?i)onload\s*="
            ],
            "Sensitive File Access": [
                r"(?i)/etc/passwd",
                r"(?i)boot\.ini",
                r"(?i)config\.php(?:\?.*)?",
                r"(?i)\.\./\.\./" # Directory traversal
            ],
            "Insecure Communication": [
                r"(?i)(password|passwd|pwd)\s*=\s*([^\s&]+)",
                r"(?i)login\s*=\s*",
                r"(?i)admin\s*=\s*"
            ]
        }
        
        # Pre-compile the regexes for performance
        self.compiled_signatures = {}
        for attack_type, patterns in self.signatures.items():
            self.compiled_signatures[attack_type] = [re.compile(p) for p in patterns]

    def _decode_payload(self, payload):
        """Attempts to decode common obfuscations like URL encoding."""
        try:
            return urllib.parse.unquote(payload)
        except Exception:
            return payload

    def inspect_payload(self, payload):
        if not payload:
            return None
            
        decoded_payload = self._decode_payload(payload)
        
        for attack_type, compiled_patterns in self.compiled_signatures.items():
            for pattern in compiled_patterns:
                match = pattern.search(decoded_payload)
                if match:
                    # Provide the actual matched string as the signature detail
                    matched_str = match.group(0)
                    # Truncate if too long
                    if len(matched_str) > 50:
                        matched_str = matched_str[:47] + "..."
                    return f"DPI ALERT: {attack_type} detected (Signature: {matched_str})"
                    
        return None