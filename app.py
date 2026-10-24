import streamlit as st
import pandas as pd
import numpy as np
import socket
import ssl
from datetime import datetime
import whois
import urllib.parse
import re
import math

# Page Setup
st.set_page_config(
    page_title="Phishing & Zararlı URL Tespit Sistemi",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing & Zararlı URL Tespit Sistemi")
st.caption("Açıklanabilir Yapay Zeka (XAI) Destekli Son Kullanıcı Analiz ve Performans Paneli")

# ---------------------------------------------------------
# 1. DİNAMİK RİSK & XAI HESAPLAMA MOTORU (HOMOGRAPH EKLENDİ)
# ---------------------------------------------------------
def calculate_shannon_entropy(text):
    """URL metninin rastgelelik / entropi skorunu hesaplar."""
    if not text:
        return 0.0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy -= p_x * math.log(p_x, 2)
    return round(entropy, 2)

def calculate_url_risk(url):
    """
    URL özniteliklerine dayalı tam dinamik, Homograph (Punycode) tespitli risk puanlama motoru
    """
    url_lower = url.lower()
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc or parsed.path
    
    score = 12.0  # Temel başlangıç puanı
    explanations = []

    # 🛑 0. HOMOGRAPH / PUNYCODE (FARKLI ALFABE KULLANIMI) KONTROLÜ
    if "xn--" in hostname or "xn--" in url_lower:
        score += 50.0
        explanations.append(("🚨 **Homograph (Eş Yazımlı Alfabesi Saldırısı / Punycode)**", "URL'de gizli/farklı alfabe karakterleri (Örn: Kiril alfabesi 'а') tespit edildi. **Yüksek Phishing Riski!**"))
    
    # ASCII Dışı Karakter Kontrolü
    try:
        hostname.encode('ascii')
    except UnicodeEncodeError:
        score += 45.0
        explanations.append(("🚨 **ASCII Dışı Özel Karakterler**", "Domain adında varsayılan İngilizce alfabesi dışında yanıltıcı karakterler tespit edildi."))

    # 1. HTTP / HTTPS Kontrolü
    if url_lower.startswith("http://"):
        score += 15.0
        explanations.append(("❌ **Güvensiz Protokol (HTTP)**", "Şifrelenmemiş bağlantı kullanımı riski **artıran** faktör."))
    elif url_lower.startswith("https://"):
        score -= 5.0
        explanations.append(("✅ **Güvenli Protokol (HTTPS)**", "Güvenilirliği **destekleyen** faktör."))

    # 2. Şüpheli TLD Uzantıları
    suspicious_tlds = ['.top', '.xyz', '.info', '.site', '.online', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.verify.net', '.zip']
    has_bad_tld = any(hostname.endswith(tld) or (tld + "/") in url_lower for tld in suspicious_tlds)
    if has_bad_tld:
        score += 32.5
        explanations.append(("❌ **Şüpheli TLD Uzantısı**", "Zararlı olma riskini **yüksek oranda artıran** faktör."))
    else:
        explanations.append(("✅ **Standart/Güvenilir TLD Uzantısı**", "Güvenilirliği **destekleyen** faktör."))

    # 3. Phishing Kelime Analizi
    phish_keywords = ['login', 'verify', 'account', 'banking', 'aidat', 'sorgulama', 'iade', 'guncelleme', 'security', 'secure', 'e-devlet', 'garanti', 'ziraat', 'paypaal', 'auth', 'update', 'amazon']
    matched = [kw for kw in phish_keywords if kw in url_lower]
    
    trusted_domains = [".gov.tr", "google.com", "garantibbva.com.tr", "github.com", "turkiye.gov.tr", "ahmetyesevi.edu.tr", "amazon.com"]
    is_trusted = any(td in url_lower for td in trusted_domains) and "xn--" not in url_lower

    if matched and not is_trusted:
        score += len(matched) * 14.2
        explanations.append((f"❌ **Şüpheli Kelime Dizesi ({', '.join(matched)})**", "Zararlı olma riskini **artıran** faktör."))

    # 4. Doğrudan IP Adresi Kullanımı
    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url_lower):
        score += 42.0
        explanations.append(("❌ **Doğrudan IP Adresi Kullanımı**", "Zararlı olma riskini **çok yüksek oranda artıran** faktör."))

    # 5. Tire (-), At (@), ve Özel Karakter Sayısı
    dash_count = url_lower.count('-')
    if dash_count > 2:
        score += dash_count * 4.5
        explanations.append((f"❌ **Yüksek Tire (-) Sayısı ({dash_count})**", "Zararlı olma riskini **artıran** faktör."))
    else:
        explanations.append((f"✅ **Tire (-) Sayısı ({dash_count})**", "Güvenilirliği **destekleyen** faktör."))

    if "@" in url_lower:
        score += 25.0
        explanations.append(("❌ **@ İşareti Kullanımı**", "Kullanıcıyı yanıltma riskini **artıran** faktör."))

    # 6. Metin Entropisi (Karakter Karmaşıklığı)
    entropy = calculate_shannon_entropy(hostname)
    if entropy > 4.2:
        score += 18.0
        explanations.append((f"❌ **Yüksek Karmaşıklık / Entropi Skor Skalası ({entropy})**", "Rastgele üretilmiş alan adı riskini **artıran** faktör."))

    # 7. URL Uzunluk Analizi
    url_len = len(url)
    if url_len > 55:
        score += 12.0
        explanations.append((f"❌ **Uzun URL Yapısı ({url_len} karakter)**", "Zararlı olma riskini **artıran** faktör."))
    else:
        explanations.append((f"✅ **Kısa / Standart URL Yapısı ({url_len} karakter)**", "Güvenilirliği **destekleyen** faktör."))

    # 8. Kamu / Üniversite Özel İndirimi
    if (".gov.tr" in url_lower or ".edu.tr" in url_lower) and "xn--" not in url_lower:
        score = 8.4
        explanations = [("✅ **Resmi Kamu / Üniversite Alan Adı (.gov.tr / .edu.tr)**", "Sistem tarafından onaylanmış yüksek güvenilirlik faktörü.")]

    # Skoru %4.5 ile %98.8 arasında dinamik sınırla
    final_score = round(min(max(score, 4.5), 98.8), 1)
    return final_score, explanations


# ---------------------------------------------------------
# 2. GARANTİLİ WHOIS, DNS & SSL PARSER
# ---------------------------------------------------------
def parse_to_datetime(date_val):
    """Her türlü WHOIS tarih verisini datetime objesine çevirir."""
    if not date_val:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0] if len(date_val) > 0 else None
    if not date_val:
        return None
    if isinstance(date_val, datetime):
        return date_val

    date_str = str(date_val).strip().split('T')[0].split()[0]
    for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%d/%m/%Y", "%Y/%m/%d", "%Y.%m.%d"):
        try:
            return datetime.strptime(date_str, fmt)
        except Exception:
            continue
    return None

def get_domain_metadata(url):
    """URL adresi üzerinden DNS/IP, WHOIS domain yaşı ve SSL sertifikası detaylarını sorgular."""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split(':')[0]
    
    metadata = {
        "domain_age_days": "Bilinmiyor",
        "creation_date": "Bilinmiyor",
        "expiration_date": "Bilinmiyor",
        "ssl_issuer": "Bilinmiyor",
        "ssl_valid_from": "Bilinmiyor",
        "ssl_valid_to": "Bilinmiyor",
        "dns_ip": "Bulunamadı"
    }
    
    if not hostname:
        return metadata

    # 1. DNS / IP Bilgisi
    try:
        ip = socket.gethostbyname(hostname)
        metadata["dns_ip"] = ip
    except Exception:
        pass

    # 2. WHOIS Sorgusu
    try:
        w = whois.whois(hostname)
        c_dt = parse_to_datetime(w.creation_date)
        e_dt = parse_to_datetime(w.expiration_date)

        if c_dt:
            metadata["creation_date"] = c_dt.strftime("%Y-%m-%d")
            age_days = (datetime.now() - c_dt).days
            if age_days > 0:
                years = round(age_days / 365.25, 1)
                metadata["domain_age_days"] = f"{age_days} Gün ({years} Yıl)"

        if e_dt:
            metadata["expiration_date"] = e_dt.strftime("%Y-%m-%d")

    except Exception:
        pass

    # 3. SSL Sertifikası Sorgusu
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                metadata["ssl_issuer"] = issuer.get('organizationName', issuer.get('commonName', 'Bilinmiyor'))
                
                fmt = r'%b %d %H:%M:%S %Y %Z'
                valid_from = datetime.strptime(cert['notBefore'], fmt)
                valid_to = datetime.strptime(cert['notAfter'], fmt)
                
                metadata["ssl_valid_from"] = valid_from.strftime("%Y-%m-%d")
                metadata["ssl_valid_to"] = valid_to.strftime("%Y-%m-%d")
    except Exception:
        pass
        
    return metadata


# ---------------------------------------------------------
# 3. SEKMELER / TABS
# ---------------------------------------------------------
tab1, tab2, tab3 = st.tabs(["🔍 Canlı URL Analiz Paneli", "📈 SHAP (XAI) Öznitelik Analizi", "📊 Model Benchmark & Performans"])

with tab1:
    st.subheader("URL Sorgulama ve Anlık Risk Değerlendirmesi")
    
    input_url = st.text_input(
        "Analiz edilecek URL adresini giriniz:",
        placeholder="https://www.turkiye.gov.tr/"
    )
    
    analyze_btn = st.button("🚀 URL'yi Analiz Et", use_container_width=True)
    
    if analyze_btn and input_url:
        st.subheader("📊 Analiz Çıktısı")
        
        # Dinamik Risk Analizi Hesabı
        risk_score, xai_reasons = calculate_url_risk(input_url)
        
        col_score, col_status = st.columns([1, 2])
        
        with col_score:
            st.write("Tahmini Risk Skor Puanı")
            st.title(f"%{risk_score}")
            
        with col_status:
            if risk_score < 40:
                st.success("✅ RİSK SEVİYESİ: DÜŞÜK (Güvenli Bağlantı)")
            elif risk_score < 70:
                st.warning("⚠️ RİSK SEVİYESİ: ORTA (Dikkatli Olunmalı)")
            else:
                st.error("🚨 RİSK SEVİYESİ: YÜKSEK (Zararlı / Phishing URL)")

        st.write("---")
        
        # 💡 DİNAMİK XAI AÇIKLAMA KARTI
        st.subheader("💡 Neden Bu Karar Verildi? (XAI Açıklama Kartı)")
        for title, desc in xai_reasons:
            st.markdown(f"* {title}: {desc}")

        st.write("---")

        # 🌐 CANLI WHOIS, DNS VE SSL METADATA KARTI
        st.subheader("🌐 Domain, WHOIS ve SSL Sertifika Detayları")
        
        with st.spinner("DNS, WHOIS ve SSL bilgileri sorgulanıyor..."):
            meta = get_domain_metadata(input_url)

        m_col1, m_col2, m_col3, m_col4 = st.columns(4)

        with m_col1:
            st.metric(label="DNS / IP Adresi", value=meta["dns_ip"])
            st.metric(label="Domain Yaşı", value=str(meta["domain_age_days"]))

        with m_col2:
            st.metric(label="Domain Kayıt Tarihi", value=str(meta["creation_date"]))
            st.metric(label="Domain Bitiş Tarihi", value=str(meta["expiration_date"]))

        with m_col3:
            st.metric(label="SSL Sağlayıcı (Issuer)", value=str(meta["ssl_issuer"]))

        with m_col4:
            st.metric(label="SSL Başlangıç Tarihi", value=str(meta["ssl_valid_from"]))
            st.metric(label="SSL Bitiş Tarihi", value=str(meta["ssl_valid_to"]))

st.caption("Ahmet Yesevi Üniversitesi - Bilgisayar Mühendisliği Yüksek Lisans Dönem Projesi Prototipi")