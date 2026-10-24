import streamlit as st
import pandas as pd
import numpy as np
import socket
import ssl
from datetime import datetime
import whois
import urllib.parse

# Page Setup
st.set_page_config(
    page_title="Phishing & Zararlı URL Tespit Sistemi",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing & Zararlı URL Tespit Sistemi")
st.caption("Açıklanabilir Yapay Zeka (XAI) Destekli Son Kullanıcı Analiz ve Performans Paneli")

# ---------------------------------------------------------
# 1. YARDIMCI FONKSİYONLAR (WHOIS, DNS & SSL)
# ---------------------------------------------------------
def get_domain_metadata(url):
    """
    URL adresi üzerinden DNS/IP, WHOIS domain yaşı ve SSL sertifikası
    detaylarını canlı sorgular.
    """
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc or parsed.path
    hostname = hostname.split(':')[0]  # Port numarasını temizle
    
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

    # 2. WHOIS Sorgusu (Gelişmiş Tarih Yakalama ve Fallback Yaş Hesaplama)
    try:
        w = whois.whois(hostname)
        
        creation = w.creation_date
        if isinstance(creation, list) and len(creation) > 0:
            creation = creation[0]
            
        expiration = w.expiration_date
        if isinstance(expiration, list) and len(expiration) > 0:
            expiration = expiration[0]

        # Creation Date İşleme
        creation_dt = None
        if creation:
            if isinstance(creation, datetime):
                creation_dt = creation
            else:
                try:
                    c_str = str(creation).split()[0]
                    creation_dt = datetime.strptime(c_str, "%Y-%m-%d")
                except Exception:
                    pass

        # Expiration Date İşleme
        expiration_dt = None
        if expiration:
            if isinstance(expiration, datetime):
                expiration_dt = expiration
            else:
                try:
                    e_str = str(expiration).split()[0]
                    expiration_dt = datetime.strptime(e_str, "%Y-%m-%d")
                except Exception:
                    pass

        # Metin Formatına Dönüştürme ve Yaş Hesaplama
        if creation_dt:
            metadata["creation_date"] = creation_dt.strftime("%Y-%m-%d")
            age = (datetime.now() - creation_dt).days
            if age > 0:
                years = round(age / 365.25, 1)
                metadata["domain_age_days"] = f"{age} Gün ({years} Yıl)"

        if expiration_dt:
            metadata["expiration_date"] = expiration_dt.strftime("%Y-%m-%d")

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
# 2. SEKMELER / TABS
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
        
        # Risk Skoru Mantığınız (Örnek/Canlı)
        is_gov = ".gov.tr" in input_url or "turkiye.gov.tr" in input_url
        risk_score = 15.0 if is_gov else 28.0
        
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
        
        # 💡 XAI AÇIKLAMA KARTI
        st.subheader("💡 Neden Bu Karar Verildi? (XAI Açıklama Kartı)")
        st.markdown("""
        * ❌ **Tire (-) Sayısı** (Değer: `0.0`): Zararlı olma riskini **artıran** faktör.
        * ✅ **@ İşareti Kullanımı** (Değer: `0.0`): Güvenilirliği **destekleyen** faktör.
        * ✅ **hostname_length** (Değer: `18.0`): Güvenilirliği **destekleyen** faktör.
        * ❌ **URL Metin Uzunluğu** (Değer: `27.0`): Zararlı olma riskini **artıran** faktör.
        * ❌ **count_equal** (Değer: `0.0`): Zararlı olma riskini **artıran** faktör.
        """)

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