"""
Feature Extractor for URL Analysis
Converts URLs into numerical feature vectors for ML prediction
Updated to 16 features to match training
"""

import re
from urllib.parse import urlparse
import numpy as np

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        """Initialize the feature extractor"""
        self.feature_names = [
            'url_length',
            'dot_count',
            'at_count',
            'has_ip',
            'subdomain_count',
            'hyphen_count',
            'underscore_count',
            'slash_count',
            'question_count',
            'equals_count',
            'is_https',
            'hostname_length',
            'digit_count',
            'letter_count',
            'has_port',
            'has_fragment'
        ]
    
    def extract_features(self, url: str) -> dict:
        """
        Extract features from a single URL
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary of feature names to values
        """
        features = {}
        
        # Normalize URL
        url = url.strip()
        
        # Basic URL length
        features['url_length'] = len(url)
        
        # Count of dots
        features['dot_count'] = url.count('.')
        
        # Count of @ symbols
        features['at_count'] = url.count('@')
        
        # Check for IP address in URL
        ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # Count of subdomains
        try:
            parsed_url = url if url.startswith(('http://', 'https://')) else f'http://{url}'
            parsed = urlparse(parsed_url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            features['subdomain_count'] = max(0, len(parts) - 2)
        except Exception:
            features['subdomain_count'] = 0
        
        # Count of hyphens
        features['hyphen_count'] = url.count('-')
        
        # Count of underscores
        features['underscore_count'] = url.count('_')
        
        # Count of slashes
        features['slash_count'] = url.count('/')
        
        # Count of question marks
        features['question_count'] = url.count('?')
        
        # Count of equals signs
        features['equals_count'] = url.count('=')
        
        # Check for HTTPS
        features['is_https'] = 1 if url.startswith('https://') else 0
        
        # Length of hostname
        try:
            parsed_url = url if url.startswith(('http://', 'https://')) else f'http://{url}'
            parsed = urlparse(parsed_url)
            features['hostname_length'] = len(parsed.hostname or '')
        except Exception:
            features['hostname_length'] = 0
        
        # Count of digits
        features['digit_count'] = sum(c.isdigit() for c in url)
        
        # Count of letters
        features['letter_count'] = sum(c.isalpha() for c in url)
        
        # NEW FEATURES (15-16)
        # Check if URL has explicit port
        try:
            parsed_url = url if url.startswith(('http://', 'https://')) else f'http://{url}'
            parsed = urlparse(parsed_url)
            features['has_port'] = 1 if parsed.port is not None else 0
        except Exception:
            features['has_port'] = 0
        
        # Check if URL has fragment/anchor
        features['has_fragment'] = 1 if '#' in url else 0
        
        return features
    
    def extract_features_vector(self, url: str) -> np.ndarray:
        """
        Extract features and return as numpy array (for ML model)
        
        Args:
            url: The URL to analyze
            
        Returns:
            Numpy array of features in correct order
        """
        features = self.extract_features(url)
        
        # Return features in consistent order
        return np.array([features[name] for name in self.feature_names]).reshape(1, -1)
    
    def get_feature_names(self) -> list:
        """
        Get list of feature names in order
        
        Returns:
            List of feature names
        """
        return self.feature_names.copy()