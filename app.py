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
# 1. HİBRİT RİSK & XAI HESAPLAMA MOTORU (HAVUZ + DNS/IP + XAI)
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

def calculate_hybrid_url_risk(url):
    """
    1. Katman: Güvenilir Domain Havuzu (Whitelist)
    2. Katman: Canlı DNS / IP Çözümleme Varlık Kontrolü
    3. Katman: Sezgisel (Heuristic) & Homograph & Marka Taklidi Analizi
    """
    url_lower = url.lower().strip()
    parsed = urllib.parse.urlparse(url_lower if url_lower.startswith(('http://', 'https://')) else f'http://{url_lower}')
    hostname = parsed.netloc or parsed.path
    hostname_clean = hostname.split(':')[0].replace("www.", "")

    # -----------------------------------------------------
    # 🟢 1. KATMAN: GÜVENİLİR DOMAİN HAVUZU (WHITELIST)
    # -----------------------------------------------------
    trusted_whitelist = [
        "turkiye.gov.tr", "e-devlet.gov.tr", "ahmetyesevi.edu.tr",
        "google.com", "github.com", "amazon.com", "garantibbva.com.tr",
        "ziraatbank.com.tr", "isbank.com.tr", "akbank.com", "vakifbank.com.tr",
        "youtube.com", "microsoft.com", "wikipedia.org", "e-devlet.gov.tr"
    ]

    # Tam eşleşme veya resmi kamu/üniversite uzantısı kontrolü
    if hostname_clean in trusted_whitelist or hostname_clean.endswith(".gov.tr") or hostname_clean.endswith(".edu.tr"):
        if "xn--" not in hostname_clean:
            return 5.0, [("✅ **Onaylı Güvenilir Havuz Kaydı (Whitelist)**", "Sistem tarafından doğrulanmış kurumsal/resmi alan adı.")]

    # -----------------------------------------------------
    # 🟡 2. KATMAN: CANLI DNS / IP ÇÖZÜMLEME VARLIK KONTROLÜ
    # -----------------------------------------------------
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname_clean)
    except Exception:
        resolved_ip = None

    if not resolved_ip:
        # İnternette aktif IP kaydı olmayan sahte/rastgele domainler (Örn: xx.org)
        return 92.5, [
            ("🚨 **Aktif DNS / IP Kaydı Bulunamadı**", f"`{hostname_clean}` domainine ait aktif bir IP adresi çözümlenemedi. **Geçersiz, Pasif veya Şüpheli Alan Adı!**"),
            ("❌ **Bilinmeyen / Yanıltıcı Domain Yapısı**", "İnternet üzerinde aktif sunucu karşılığı olmayan adresler yüksek risk taşır.")
        ]

    # -----------------------------------------------------
    # 🔴 3. KATMAN: SEZGİSEL (HEURISTIC) & MARKA TAKLİDİ ANALİZİ
    # -----------------------------------------------------
    score = 15.0  # Varsayılan başlangıç puanı
    explanations = []

    explanations.append((f"🌐 **Aktif IP Adresi Doğrulandı ({resolved_ip})**", "Domain internet üzerinde aktif bir IP adresine yönleniyor."))

    # Marka / Kamu Kurumu Taklidi (Typosquatting)
    critical_brands = ['turkiye', 'edevlet', 'e-devlet', 'garanti', 'ziraat', 'vakifbank', 'isbank', 'akbank', 'gib', 'mhrs']
    for brand in critical_brands:
        if brand in hostname_clean:
            if brand in ['turkiye', 'edevlet', 'e-devlet', 'gib', 'mhrs'] and not hostname_clean.endswith(".gov.tr"):
                score += 55.0
                explanations.append((f"🚨 **Marka/Kamu Kurumu Taklidi ({brand})**", f"URL resmi kamu uzantısı (.gov.tr) taşımıyor! **Sahte/Taklit Domain Riski!**"))
            elif brand in ['garanti', 'ziraat', 'vakifbank', 'isbank', 'akbank'] and not any(hostname_clean.endswith(ok) for ok in [f"{brand}.com.tr", f"{brand}bbva.com.tr", f"{brand}.com"]):
                score += 50.0
                explanations.append((f"🚨 **Banka/Kurum Taklidi ({brand})**", f"URL resmi banka domain yapısıyla eşleşmiyor. **Phishing Riski!**"))

    # Homograph / Punycode (Farklı Alfabe Kullanımı)
    if "xn--" in hostname_clean or "xn--" in url_lower:
        score += 50.0
        explanations.append(("🚨 **Homograph (Eş Yazımlı Alfabesi Saldırısı / Punycode)**", "URL'de gizli/farklı alfabe karakterleri (Örn: Kiril alfabesi 'а') tespit edildi. **Yüksek Phishing Riski!**"))

    # HTTP / HTTPS Kontrolü
    if url_lower.startswith("http://"):
        score += 15.0
        explanations.append(("❌ **Güvensiz Protokol (HTTP)**", "Şifrelenmemiş bağlantı kullanımı riski **artıran** faktör."))
    elif url_lower.startswith("https://"):
        score -= 5.0
        explanations.append(("✅ **Güvenli Protokol (HTTPS)**", "Güvenilirliği **destekleyen** faktör."))

    # Şüpheli TLD Uzantıları
    suspicious_tlds = ['.top', '.xyz', '.info', '.site', '.online', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.verify.net', '.zip']
    has_bad_tld = any(hostname_clean.endswith(tld) or (tld + "/") in url_lower for tld in suspicious_tlds)
    if has_bad_tld:
        score += 32.5
        explanations.append(("❌ **Şüpheli TLD Uzantısı**", "Zararlı olma riskini **yüksek oranda artıran** faktör."))
    else:
        explanations.append(("✅ **Standart TLD Uzantısı**", "Güvenilirliği **destekleyen** faktör."))

    # Phishing Kelime Analizi
    phish_keywords = ['login', 'verify', 'account', 'banking', 'aidat', 'sorgulama', 'iade', 'guncelleme', 'security', 'secure', 'paypaal', 'auth', 'update']
    matched = [kw for kw in phish_keywords if kw in url_lower]
    if matched:
        score += len(matched) * 14.2
        explanations.append((f"❌ **Şüpheli Kelime Dizesi ({', '.join(matched)})**", "Zararlı olma riskini **artıran** faktör."))

    # Doğrudan IP Adresi Kullanımı
    ip_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
    if re.search(ip_pattern, url_lower):
        score += 42.0
        explanations.append(("❌ **Doğrudan IP Adresi Kullanımı**", "Zararlı olma riskini **çok yüksek oranda artıran** faktör."))

    # Tire (-) ve At (@) Sayısı
    dash_count = url_lower.count('-')
    if dash_count > 2:
        score += dash_count * 4.5
        explanations.append((f"❌ **Yüksek Tire (-) Sayısı ({dash_count})**", "Zararlı olma riskini **artıran** faktör."))

    if "@" in url_lower:
        score += 25.0
        explanations.append(("❌ **@ İşareti Kullanımı**", "Kullanıcıyı yanıltma riskini **artıran** faktör."))

    # Metin Entropisi (Karakter Karmaşıklığı)
    entropy = calculate_shannon_entropy(hostname_clean)
    if entropy > 4.2:
        score += 18.0
        explanations.append((f"❌ **Yüksek Karmaşıklık / Entropi Skor Skalası ({entropy})**", "Rastgele üretilmiş alan adı riskini **artıran** faktör."))

    final_score = round(min(max(score, 5.0), 98.8), 1)
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
        
        # Hibrit Risk Analizi Hesabı (Whitelist -> DNS -> Feature Matrix)
        with st.spinner("URL güvenlik havuzu, DNS ve öznitelikler sorgulanıyor..."):
            risk_score, xai_reasons = calculate_hybrid_url_risk(input_url)
        
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