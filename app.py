import streamlit as st
import pandas as pd
import numpy as np
import pickle
import shap
import matplotlib.pyplot as plt
from dataset_builder import extract_all_features

# Sayfa Yapılandırması (Geniş Düzen)
st.set_page_config(
    page_title="Phishing XAI Detector",
    page_icon="🛡️",
    layout="wide"
)

# Model ve Varlıkları Yükleme
@st.cache_resource
def load_assets():
    with open("best_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("shap_explainer.pkl", "rb") as f:
        explainer = pickle.load(f)
    with open("feature_names.pkl", "rb") as f:
        feature_names = pickle.load(f)
    with open("metrics.pkl", "rb") as f:
        metrics = pickle.load(f)
    return model, explainer, feature_names, metrics

try:
    model, explainer, feature_names, metrics = load_assets()
    assets_loaded = True
except Exception as e:
    assets_loaded = False

# Üst Başlık
st.title("🛡️ Phishing & Zararlı URL Tespit Sistemi")
st.caption("Açıklanabilir Yapay Zeka (XAI) Destekli Son Kullanıcı Analiz ve Performans Paneli")

st.markdown("---")

if not assets_loaded:
    st.error("Model varlıkları yüklenemedi. Lütfen önce `train_model.py` betiğini çalıştırın.")
    st.stop()

# 3 Ana Sekme Oluşturma
tab1, tab2, tab3 = st.tabs(["🔍 Canlı URL Analiz Paneli", "📈 SHAP (XAI) Öznitelik Analizi", "📊 Model Benchmark & Performans"])

# ==========================================
# SEKMELER 1: CANLI ANALİZ
# ==========================================
with tab1:
    st.subheader("URL Sorgulama ve Anlık Risk Değerlendirmesi")
    url_input = st.text_input("Analiz edilecek URL adresini giriniz:", placeholder="https://login-garanti-bankasi.com-verify.net")
    
    if st.button("🚀 URL'yi Analiz Et", use_container_width=True):
        if not url_input.strip():
            st.warning("Lütfen geçerli bir URL giriniz.")
        else:
            with st.spinner("Öznitelikler çıkarılıyor (URL + SSL + WHOIS + Entropi)..."):
                raw_feats = extract_all_features(url_input)
                df_feats = pd.DataFrame([raw_feats])
                
                for col in feature_names:
                    if col not in df_feats.columns:
                        df_feats[col] = 0
                
                X_input = df_feats[feature_names]
                prob_phishing = model.predict_proba(X_input)[0][1] * 100
                
                # SHAP Hesaplama
                shap_vals = explainer.shap_values(X_input)
                if isinstance(shap_vals, list):
                    shap_vec = np.array(shap_vals[1]).flatten() if len(shap_vals) > 1 else np.array(shap_vals[0]).flatten()
                else:
                    shap_vec = np.array(shap_vals).flatten()
                shap_vec = shap_vec[:len(feature_names)]
            
            st.markdown("### 📊 Analiz Çıktısı")
            c1, c2 = st.columns(2)
            with c1:
                st.metric(label="Tahmini Risk Skor Puanı", value=f"%{prob_phishing:.1f}")
            with c2:
                if prob_phishing >= 70:
                    st.error("⚠️ RİSK SEVİYESİ: YÜKSEK (Zararlı Bağlantı)")
                elif prob_phishing >= 40:
                    st.warning("⚡ RİSK SEVİYESİ: ORTA (Şüpheli Bağlantı)")
                else:
                    st.success("✅ RİSK SEVİYESİ: DÜŞÜK (Güvenli Bağlantı)")
            
            st.markdown("---")
            st.subheader("💡 Neden Bu Karar Verildi? (XAI Açıklama Kartı)")
            
            impact_df = pd.DataFrame({
                'Öznitelik': feature_names,
                'Değer': X_input.iloc[0].values,
                'Etki': shap_vec
            }).sort_values(by='Etki', key=abs, ascending=False)
            
            feat_descriptions = {
                'domain_age_days': 'Alan Adı Yaşı (Gün)',
                'ssl_age_days': 'SSL Sertifikası Yaşı (Gün)',
                'ssl_issuer_free': 'Ücretsiz/Kısa Süreli SSL Kullanımı',
                'is_https': 'HTTPS Protokolü Varlığı',
                'url_length': 'URL Metin Uzunluğu',
                'url_entropy': 'URL Entropisi (Karmaşıklık Derecesi)',
                'brand_imitation': 'Marka Taklidi / Typosquatting Şüphesi',
                'count_dots': 'Nokta Sayısı',
                'count_hyphens': 'Tire (-) Sayısı',
                'subdomain_count': 'Alt Alan Adı Derinliği',
                'count_at': '@ İşareti Kullanımı',
                'has_ip': 'IP Adresi İle Doğrudan Erişim'
            }
            
            for _, row in impact_df.head(5).iterrows():
                fname = feat_descriptions.get(row['Öznitelik'], row['Öznitelik'])
                val = row['Değer']
                impact = row['Etki']
                
                if impact > 0:
                    st.write(f"❌ **{fname}** (Değer: `{val}`): Zararlı olma riskini **artıran** faktör.")
                else:
                    st.write(f"✅ **{fname}** (Değer: `{val}`): Güvenilirliği **destekleyen** faktör.")

# ==========================================
# SEKMELER 2: SHAP (XAI) ANALİZİ (DÜZELTİLEN KISIM)
# ==========================================
with tab2:
    st.subheader("Açıklanabilir Yapay Zeka (XAI) Öznitelik Önem Düzeyleri")
    st.write("Aşağıdaki grafik, eğitilen makine öğrenmesi modelinin zararlı URL tespiti yaparken **en çok hangi özniteliklere güvendiğini** göstermektedir:")
    
    try:
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
        else:
            importances = np.ones(len(feature_names)) / len(feature_names)
            
        df_imp = pd.DataFrame({
            'Öznitelik': feature_names,
            'Önem Derecesi': importances
        }).sort_values(by='Önem Derecesi', ascending=True)
        
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.barh(df_imp['Öznitelik'], df_imp['Önem Derecesi'], color='#2b6cb0')
        ax.set_xlabel("Göreli Önem Derecesi (Feature Importance)")
        ax.set_title("Modelin Karar Mekanizmasında En Etkili Faktörler")
        plt.tight_layout()
        st.pyplot(fig)
    except Exception as e:
        st.error(f"Grafik oluşturulurken bir hata oluştu: {e}")

# ==========================================
# SEKMELER 3: BENCHMARK
# ==========================================
with tab3:
    st.subheader("Modellerin Karşılaştırmalı Performans Analizi")
    st.write("Projede test edilen 3 farklı makine öğrenmesi algoritmasının metrikleri:")
    
    df_metrics = pd.DataFrame(metrics).T
    df_metrics = df_metrics.map(lambda x: f"%{x*100:.2f}")
    
    st.table(df_metrics)
    
    st.info("💡 **Sonuç:** Random Forest ve XGBoost modelleri özellikle düşük Yanlış Pozitif (False Positive) oranı ve yüksek F1-Skoru ile öne çıkmaktadır.")

st.markdown("---")
st.caption("Ahmet Yesevi Üniversitesi - Bilgisayar Mühendisliği Yüksek Lisans Dönem Projesi Prototipi")