import pandas as pd
import numpy as np

def generate_robust_dataset(n_samples=400):
    print("Zenginleştirilmiş Veri Seti Oluşturuluyor...")
    np.random.seed(42)
    n_each = n_samples // 2
    
    # Phishing (Label = 1)
    phish_data = {
        'url_length': np.random.randint(50, 160, n_each),
        'hostname_length': np.random.randint(15, 45, n_each),
        'url_entropy': np.random.uniform(4.2, 5.8, n_each),
        'count_dots': np.random.randint(3, 7, n_each),
        'count_hyphens': np.random.randint(1, 5, n_each),
        'count_at': np.random.choice([0, 1], size=n_each, p=[0.7, 0.3]),
        'count_question': np.random.choice([0, 1, 2], size=n_each, p=[0.5, 0.4, 0.1]),
        'count_equal': np.random.choice([0, 1, 2, 3], size=n_each, p=[0.4, 0.3, 0.2, 0.1]),
        'count_slash': np.random.randint(3, 8, n_each),
        'has_ip': np.random.choice([0, 1], size=n_each, p=[0.8, 0.2]),
        'subdomain_count': np.random.randint(2, 5, n_each),
        'is_https': np.random.choice([0, 1], size=n_each, p=[0.4, 0.6]),
        'brand_imitation': np.random.choice([0, 1], size=n_each, p=[0.3, 0.7]), # Yüksek taklit
        'ssl_valid': np.random.choice([0, 1], size=n_each, p=[0.5, 0.5]),
        'ssl_issuer_free': np.random.choice([0, 1], size=n_each, p=[0.2, 0.8]),
        'ssl_age_days': np.random.randint(1, 30, n_each),
        'domain_age_days': np.random.randint(1, 60, n_each),
        'whois_has_data': np.random.choice([0, 1], size=n_each, p=[0.6, 0.4]),
        'label': 1
    }
    
    # Benign (Label = 0)
    benign_data = {
        'url_length': np.random.randint(15, 45, n_each),
        'hostname_length': np.random.randint(8, 20, n_each),
        'url_entropy': np.random.uniform(2.5, 4.1, n_each),
        'count_dots': np.random.randint(1, 3, n_each),
        'count_hyphens': np.random.randint(0, 2, n_each),
        'count_at': np.zeros(n_each, dtype=int),
        'count_question': np.random.choice([0, 1], size=n_each, p=[0.8, 0.2]),
        'count_equal': np.random.choice([0, 1], size=n_each, p=[0.8, 0.2]),
        'count_slash': np.random.randint(1, 4, n_each),
        'has_ip': np.zeros(n_each, dtype=int),
        'subdomain_count': np.random.randint(0, 2, n_each),
        'is_https': np.ones(n_each, dtype=int),
        'brand_imitation': np.zeros(n_each, dtype=int),
        'ssl_valid': np.ones(n_each, dtype=int),
        'ssl_issuer_free': np.random.choice([0, 1], size=n_each, p=[0.8, 0.2]),
        'ssl_age_days': np.random.randint(100, 1000, n_each),
        'domain_age_days': np.random.randint(365, 5000, n_each),
        'whois_has_data': np.ones(n_each, dtype=int),
        'label': 0
    }
    
    df_phish = pd.DataFrame(phish_data)
    df_benign = pd.DataFrame(benign_data)
    
    df = pd.concat([df_phish, df_benign], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    df['url'] = [f"https://sample-site-{i}.com" for i in range(len(df))]
    
    df.to_csv("phishing_dataset.csv", index=False)
    print(f"Başarılı! Toplam {len(df)} satırlık zenginleştirilmiş veri seti 'phishing_dataset.csv' olarak kaydedildi.")

if __name__ == "__main__":
    generate_robust_dataset(400)