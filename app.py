import streamlit as st
import pandas as pd
import numpy as np
import socket
import ssl
from datetime import datetime
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
# 1. DİNAMİK RİSK & XAI HESAPLAMA MOTORU
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
    URL özniteliklerine, Homograph saldırılarına ve marka taklitlerine dayalı risk puanlama motoru.
    """
    url_lower = url.lower()
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc or parsed.path
    hostname_clean = hostname.split(':')[0]
    
    score = 12.0  # Temel başlangıç puanı
    explanations = []

    # 🛑 0. MARKA / KURUM TAKLİDİ (TYPOSQUATTING) KONTROLÜ
    critical_brands = ['turkiye', 'edevlet', 'e-devlet', 'garanti', 'ziraat', 'vakifbank', 'isbank', 'akbank', 'gib', 'mhrs']
    for brand in critical_brands:
        if brand in hostname_clean:
            # Kamu markası ama resmi .gov.tr değilse -> Yüksek Risk!
            if brand in ['turkiye', 'edevlet', 'e-devlet', 'gib', 'mhrs'] and not hostname_clean.endswith(".gov.tr"):
                score += 55.0
                explanations.append((f"🚨 **Marka/Kamu Kurumu Taklidi ({brand})**", f"URL resmi kamu uzantısı (.gov.tr) taşımıyor! **Sahte/Taklit Domain Riski!**"))
            # Banka markası ama resmi domaini değilse
            elif brand in ['garanti', 'ziraat', 'vakifbank', 'isbank', 'akbank'] and not any(hostname_clean.endswith(ok) for ok in [f"{brand}.com.tr", f"{brand}bbva.com.tr", f"{brand}.com"]):
                score += 50.0
                explanations.append((f"🚨 **Banka/Kurum Taklidi ({brand})**", f"URL resmi banka domain yapısıyla eşleşmiyor. **Phishing Riski!**"))

    # 🛑 1. HOMOGRAPH / PUNYCODE KONTROLÜ (FARKLI ALFABE KULLANIMI)
    if "xn--" in hostname_clean or "xn--" in url_lower:
        score += 50.0
        explanations.append(("🚨 **Homograph (Eş Yazımlı Alfabesi Saldırısı / Punycode)**", "URL'de gizli/farklı alfabe karakterleri (Örn: Kiril alfabesi 'а') tespit edildi. **Yüksek Phishing Riski!**"))

    # 2. HTTP / HTTPS Kontrolü
    if url_lower.startswith("http://"):
        score += 15.0
        explanations.append(("❌ **Güvensiz Protokol (HTTP)**", "Şifrelenmemiş bağlantı kullanımı riski **artıran** faktör."))
    elif url_lower.startswith("https://"):
        score -= 5.0
        explanations.append(("✅ **Güvenli Protokol (HTTPS)**", "Güvenilirliği **destekleyen** faktör."))

    # 3. Şüpheli TLD Uzantıları
    suspicious_tlds = ['.top', '.xyz', '.info', '.site', '.online', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.verify.net', '.zip']
    has_bad_tld = any(hostname_clean.endswith(tld) or (tld + "/") in url_lower for tld in suspicious_tlds)
    if has_bad_tld:
        score += 32.5
        explanations.append(("❌ **Şüpheli TLD Uzantısı**", "Zararlı olma riskini **yüksek oranda artıran** faktör."))
    else:
        explanations.append(("✅ **Standart TLD Uzantısı**", "Güvenilirliği **destekleyen** faktör."))

    # 4. Phishing Kelime Analizi
    phish_keywords = ['login', 'verify', 'account', 'banking', 'aidat', 'sorgulama', 'iade', 'guncelleme', 'security', 'secure', 'paypaal', 'auth', 'update']
    matched = [kw for kw in phish_keywords if kw in url_lower]
    
    trusted_domains = [".gov.tr", "google.com", "garantibbva.com.tr", "github.com", "ahmetyesevi.edu.tr", "amazon.com"]
    is_trusted = any(td in url_lower for td in trusted_domains) and "xn--" not in url_lower

    if matched and not is_trusted:
        score += len(matched) * 14.2
        explanations.append((f"❌ **Şüpheli Kelime Dizesi ({', '.join(matched)})**", "Zararlı olma riskini **artıran** faktör."))

    # 5. Doğrudan IP Adresi Kullanımı
    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url_lower):
        score += 42.0
        explanations.append(("❌ **Doğrudan IP Adresi Kullanımı**", "Zararlı olma riskini **çok yüksek oranda artıran** faktör."))

    # 6. Tire (-), At (@) Sayısı
    dash_count = url_lower.count('-')
    if dash_count > 2:
        score += dash_count * 4.5
        explanations.append((f"❌ **Yüksek Tire (-) Sayısı ({dash_count})**", "Zararlı olma riskini **artıran** faktör."))
    else:
        explanations.append((f"✅ **Tire (-) Sayısı ({dash_count})**", "Güvenilirliği **destekleyen** faktör."))

    if "@" in url_lower:
        score += 25.0
        explanations.append(("❌ **@ İşareti Kullanımı**", "Kullanıcıyı yanıltma riskini **artıran** faktör."))

    # 7. Metin Entropisi (Karakter Karmaşıklığı)
    entropy = calculate_shannon_entropy(hostname_clean)
    if entropy > 4.2:
        score += 18.0
        explanations.append((f"❌ **Yüksek Karmaşıklık / Entropi Skor Skalası ({entropy})**", "Rastgele üretilmiş alan adı riskini **artıran** faktör."))

    # 8. Kamu / Üniversite Özel İndirimi
    if (".gov.tr" in url_lower or ".edu.tr" in url_lower) and "xn--" not in url_lower:
        score = 8.4
        explanations = [("✅ **Resmi Kamu / Üniversite Alan Adı (.gov.tr / .edu.tr)**", "Sistem tarafından onaylanmış yüksek güvenilirlik faktörü.")]

    # Skoru %4.5 ile %98.8 arasında dinamik sınırla
    final_score = round(min(max(score, 4.5), 98.8), 1)
    return final_score, explanations


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
        
        # Dinamik Risk Skoru Hesabı
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

st.caption("Ahmet Yesevi Üniversitesi - Bilgisayar Mühendisliği Yüksek Lisans Dönem Projesi Prototipi")