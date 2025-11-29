#!/usr/bin/env python3
"""
Advanced Phishing Detection System
Combines multiple detection techniques for maximum accuracy
"""

import re
import urllib.parse
import requests
import sqlite3
import json
import pickle
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
import logging
from typing import Dict, List, Tuple, Optional

class PhishingDetector:
    def __init__(self):
        self.setup_logging()
        self.setup_database()
        self.load_ml_model()
        self.load_blacklists()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('PhishingDetector')
        
    def setup_database(self):
        """Initialize SQLite database for storing URLs and detection results"""
        self.conn = sqlite3.connect('phishing_data.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                domain TEXT,
                risk_score REAL,
                is_phishing BOOLEAN,
                detection_methods TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                domain TEXT PRIMARY KEY,
                reason TEXT,
                added_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
        
    def load_ml_model(self):
        """Load pre-trained machine learning model"""
        try:
            # In production, load actual trained model
            # For demo, using a simple rule-based approach with ML-like scoring
            self.ml_model = self.create_rule_based_model()
            self.logger.info("ML model loaded successfully")
        except Exception as e:
            self.logger.error(f"Failed to load ML model: {e}")
            self.ml_model = None
            
    def create_rule_based_model(self):
        """Create a comprehensive rule-based detection system"""
        return {
            'suspicious_keywords': [
                'login', 'signin', 'verify', 'update', 'confirm', 'security',
                'account', 'bank', 'paypal', 'amazon', 'facebook', 'google',
                'secure', 'authentication', 'validation'
            ],
            'suspicious_tlds': [
                '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click',
                '.download', '.work', '.party', '.racing', '.accountant'
            ],
            'legitimate_tlds': [
                '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int'
            ],
            'suspicious_patterns': [
                r'\d+\.\d+\.\d+\.\d+',  # IP address
                r'[-_]{2,}',                # Multiple hyphens/underscores
                r'\.\d+\.',               # Numeric subdomain
                r'[a-z0-9]{30,}',           # Very long random strings
            ]
        }
        
    def load_blacklists(self):
        """Load known phishing domains from various sources"""
        self.blacklisted_domains = set()
        
        # Add some common phishing domains for demo
        common_phishing_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'phishing-site.com', 'fake-login.net', 'scam-bank.org'
        ]
        
        for domain in common_phishing_domains:
            self.blacklisted_domains.add(domain)
            
        # Load from database
        self.cursor.execute("SELECT domain FROM blacklist")
        for row in self.cursor.fetchall():
            self.blacklisted_domains.add(row[0])
            
    def extract_url_features(self, url: str) -> Dict:
        """Extract comprehensive features from URL for analysis"""
        features = {}
        parsed = urlparse(url)
        
        # Basic URL features
        features['url_length'] = len(url)
        features['domain_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        
        # Domain analysis
        domain_parts = parsed.netloc.split('.')
        features['subdomain_count'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
        features['tld'] = '.' + '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else ''
        
        # Character distribution
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['at_symbol_count'] = url.count('@')
        features['percent_count'] = url.count('%')
        features['slash_count'] = url.count('/')
        features['question_count'] = url.count('?')
        features['equal_count'] = url.count('=')
        
        # Security indicators
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_http'] = 1 if parsed.scheme == 'http' else 0
        features['has_www'] = 1 if 'www.' in parsed.netloc else 0
        features['has_ip'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.netloc) else 0
        
        # Suspicious patterns
        features['has_suspicious_keywords'] = 0
        for keyword in self.ml_model['suspicious_keywords']:
            if keyword.lower() in url.lower():
                features['has_suspicious_keywords'] = 1
                break
                
        # Entropy calculation (randomness measure)
        features['entropy'] = self.calculate_entropy(url)
        
        return features
        
    def calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string"""
        import math
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
        
    def check_blacklist(self, url: str) -> bool:
        """Check if URL or domain is in blacklist"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check exact domain
        if domain in self.blacklisted_domains:
            return True
            
        # Check subdomains
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            subdomain = '.'.join(domain_parts[i:])
            if subdomain in self.blacklisted_domains:
                return True
                
        return False
        
    def heuristic_analysis(self, url: str) -> Dict:
        """Perform heuristic analysis on URL"""
        score = 0
        reasons = []
        
        # URL length analysis
        if len(url) > 100:
            score += 20
            reasons.append("Very long URL")
        elif len(url) < 20:
            score += 10
            reasons.append("Very short URL (suspicious)")
            
        # Domain analysis
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            score += 50
            reasons.append("Uses IP address instead of domain")
            
        # Check for suspicious TLD
        if any(tld in domain for tld in self.ml_model['suspicious_tlds']):
            score += 30
            reasons.append("Suspicious top-level domain")
            
        # Check for excessive subdomains
        if domain.count('.') > 3:
            score += 25
            reasons.append("Excessive number of subdomains")
            
        # Check for suspicious patterns
        for pattern in self.ml_model['suspicious_patterns']:
            if re.search(pattern, url, re.IGNORECASE):
                score += 30
                reasons.append("Suspicious pattern detected")
                break
                
        # Check for HTTPS on sensitive pages
        if any(keyword in url.lower() for keyword in ['login', 'signin', 'password']):
            if not parsed.scheme == 'https':
                score += 40
                reasons.append("Sensitive page without HTTPS")
                
        return {'score': score, 'reasons': reasons}
        
    def ml_analysis(self, url: str) -> Dict:
        """Perform machine learning-based analysis"""
        features = self.extract_url_features(url)
        
        # Calculate risk score based on features
        risk_score = 0
        
        # Length-based scoring
        if features['url_length'] > 75:
            risk_score += 15
        if features['domain_length'] > 50:
            risk_score += 20
            
        # Character-based scoring
        if features['dot_count'] > 5:
            risk_score += 10
        if features['hyphen_count'] > 3:
            risk_score += 15
        if features['at_symbol_count'] > 0:
            risk_score += 25
            
        # Security scoring
        if not features['has_https']:
            risk_score += 20
        if features['has_suspicious_keywords']:
            risk_score += 30
            
        # Entropy scoring
        if features['entropy'] > 4.5:
            risk_score += 25
            
        # Domain-based scoring
        if features['subdomain_count'] > 2:
            risk_score += 15
        if features['tld'] in self.ml_model['suspicious_tlds']:
            risk_score += 35
            
        return {
            'risk_score': risk_score,
            'features': features,
            'confidence': min(risk_score * 2, 100)
        }
        
    def content_analysis(self, url: str) -> Dict:
        """Analyze webpage content for phishing indicators"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            content = response.text.lower()
            
            score = 0
            reasons = []
            
            # Check for forms
            if '<form' in content:
                if any(field in content for field in ['password', 'credit card', 'ssn', 'social security']):
                    score += 40
                    reasons.append("Sensitive form fields detected")
                    
            # Check for suspicious content
            suspicious_content = [
                'verify your identity', 'confirm your account', 'update your information',
                'suspended account', 'unauthorized access', 'security breach'
            ]
            
            for phrase in suspicious_content:
                if phrase in content:
                    score += 25
                    reasons.append(f"Suspicious content: {phrase}")
                    
            # Check for external resources
            external_links = content.count('src="http') + content.count('href="http')
            if external_links > 10:
                score += 20
                reasons.append("Excessive external resources")
                
            return {'score': score, 'reasons': reasons}
            
        except Exception as e:
            self.logger.error(f"Content analysis failed: {e}")
            return {'score': 0, 'reasons': []}
            
    def analyze_url(self, url: str) -> Dict:
        """Comprehensive URL analysis using multiple techniques"""
        self.logger.info(f"Analyzing URL: {url}")
        
        # Initialize results
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'is_phishing': False,
            'risk_score': 0,
            'confidence': 0,
            'detection_methods': [],
            'reasons': []
        }
        
        # Check blacklist first
        if self.check_blacklist(url):
            results['is_phishing'] = True
            results['risk_score'] += 80
            results['detection_methods'].append('blacklist')
            results['reasons'].append("URL found in phishing blacklist")
            
        # Heuristic analysis
        heuristic = self.heuristic_analysis(url)
        results['risk_score'] += heuristic['score']
        if heuristic['score'] > 0:
            results['detection_methods'].append('heuristic')
            results['reasons'].extend(heuristic['reasons'])
            
        # Machine learning analysis
        ml_result = self.ml_analysis(url)
        results['risk_score'] += ml_result['risk_score']
        results['confidence'] = max(results['confidence'], ml_result['confidence'])
        if ml_result['risk_score'] > 0:
            results['detection_methods'].append('machine_learning')
            
        # Content analysis (if URL seems suspicious)
        if results['risk_score'] > 30:
            try:
                content_result = self.content_analysis(url)
                results['risk_score'] += content_result['score']
                if content_result['score'] > 0:
                    results['detection_methods'].append('content_analysis')
                    results['reasons'].extend(content_result['reasons'])
            except Exception as e:
                self.logger.error(f"Content analysis error: {e}")
                
        # Final classification
        if results['risk_score'] >= 60:
            results['is_phishing'] = True
        elif results['risk_score'] >= 40:
            results['is_phishing'] = None  # Suspicious
        else:
            results['is_phishing'] = False
            
        # Store results in database
        self.store_analysis(results)
        
        return results
        
    def store_analysis(self, results: Dict):
        """Store analysis results in database"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO url_analysis 
                (url, domain, risk_score, is_phishing, detection_methods)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                results['url'],
                urlparse(results['url']).netloc,
                results['risk_score'],
                results['is_phishing'],
                ','.join(results['detection_methods'])
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Database error: {e}")
            
    def add_to_blacklist(self, domain: str, reason: str = "User reported"):
        """Add domain to blacklist"""
        try:
            self.cursor.execute('''
                INSERT OR IGNORE INTO blacklist (domain, reason)
                VALUES (?, ?)
            ''', (domain, reason))
            self.conn.commit()
            self.blacklisted_domains.add(domain)
            self.logger.info(f"Added {domain} to blacklist")
        except Exception as e:
            self.logger.error(f"Blacklist update error: {e}")
            
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        try:
            self.cursor.execute('''
                SELECT 
                    COUNT(*) as total_analyzed,
                    SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing_detected,
                    AVG(risk_score) as avg_risk_score
                FROM url_analysis
            ''')
            result = self.cursor.fetchone()
            
            return {
                'total_analyzed': result[0] or 0,
                'phishing_detected': result[1] or 0,
                'avg_risk_score': round(result[2] or 0, 2)
            }
        except Exception as e:
            self.logger.error(f"Statistics error: {e}")
            return {'total_analyzed': 0, 'phishing_detected': 0, 'avg_risk_score': 0}
            
    def close(self):
        """Close database connection"""
        self.conn.close()


# Flask API for browser extension communication
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

detector = PhishingDetector()

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """API endpoint for URL analysis"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        results = detector.analyze_url(url)
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/blacklist', methods=['POST'])
def add_blacklist():
    """API endpoint to add domain to blacklist"""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        reason = data.get('reason', 'User reported')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        detector.add_to_blacklist(domain, reason)
        return jsonify({'success': True, 'message': f'{domain} added to blacklist'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """API endpoint for detection statistics"""
    try:
        stats = detector.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'phishing-detector'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)