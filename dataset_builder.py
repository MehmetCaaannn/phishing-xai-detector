import os
import ssl
import socket
import datetime
import math
import pandas as pd
import urllib.parse
import tldextract
import whois

# Popüler Markalar (Typosquatting & Marka Taklidi Tespiti İçin)
TARGET_BRANDS = [
    'google', 'microsoft', 'apple', 'facebook', 'instagram', 'paypal', 
    'amazon', 'netflix', 'binance', 'garanti', 'ziraat', 'isbank', 'akbank'
]

def calculate_entropy(text):
    """Metnin rastgelelik / karmaşıklık (Entropi) değerini hesaplar."""
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy -= p_x * math.log2(p_x)
    return entropy

def check_brand_similarity(hostname):
    """Marka taklidi (Typosquatting) var mı kontrol eder."""
    hostname_clean = hostname.lower().replace('-', '').replace('.', '')
    for brand in TARGET_BRANDS:
        if brand in hostname_clean and hostname_clean != brand:
            return 1  # Marka ismi geçiyor ama resmi domain değil!
    return 0

def extract_url_features(url):
    """Gelişmiş URL Leksikal (metin) özniteliklerini çıkarır."""
    parsed = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)
    
    hostname = parsed.netloc or parsed.path.split('/')[0]
    
    return {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'url_entropy': calculate_entropy(url),
        'count_dots': url.count('.'),
        'count_hyphens': url.count('-'),
        'count_at': url.count('@'),
        'count_question': url.count('?'),
        'count_equal': url.count('='),
        'count_slash': url.count('/'),
        'has_ip': 1 if hostname.replace('.', '').isdigit() else 0,
        'subdomain_count': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'is_https': 1 if parsed.scheme == 'https' else 0,
        'brand_imitation': check_brand_similarity(hostname)
    }

def extract_ssl_features(domain):
    """Gelişmiş SSL/TLS Sertifikası metaverilerini çıkarır."""
    features = {
        'ssl_valid': 0,
        'ssl_issuer_free': 0,
        'ssl_age_days': 0
    }
    try:
        context = ssl.create_default_context()
        context.timeout = 2.0
        with socket.create_connection((domain, 443), timeout=2.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                features['ssl_valid'] = 1
                
                issuer = str(cert.get('issuer', ''))
                if "Let's Encrypt" in issuer or "Cloudflare" in issuer or "cPanel" in issuer:
                    features['ssl_issuer_free'] = 1
                
                not_before_str = cert.get('notBefore')
                if not_before_str:
                    not_before = datetime.datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    features['ssl_age_days'] = (datetime.datetime.utcnow() - not_before).days
    except Exception:
        pass
    return features

def extract_whois_features(domain):
    """WHOIS ve Alan Adı Yaşı özniteliklerini çıkarır."""
    features = {
        'domain_age_days': -1,
        'whois_has_data': 0
    }
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            features['whois_has_data'] = 1
            age = (datetime.datetime.now() - creation_date).days
            features['domain_age_days'] = max(0, age)
    except Exception:
        pass
    return features

def extract_all_features(url):
    """Tüm gelişmiş öznitelikleri birleştirir."""
    features = {'url': url}
    features.update(extract_url_features(url))
    
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    
    features.update(extract_ssl_features(domain))
    features.update(extract_whois_features(domain))
    
    return features