import pandas as pd
import numpy as np
import pickle
import shap
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

print("1/4 Zenginleştirilmiş veri seti yükleniyor...")
df = pd.read_csv("phishing_dataset.csv")

feature_cols = [c for c in df.columns if c not in ['url', 'label']]
X = df[feature_cols]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("\n2/4 Modeller eğitiliyor ve benchmark metrikleri hesaplanıyor...")

models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "XGBoost": XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42),
    "LightGBM": LGBMClassifier(random_state=42, verbose=-1)
}

results = {}
best_model = None
best_f1 = 0
best_model_name = ""

for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    results[name] = {"Accuracy": acc, "Precision": prec, "Recall": rec, "F1-Score": f1}
    print(f"[{name}] F1-Score: %{f1*100:.2f} | Accuracy: %{acc*100:.2f}")
    
    if f1 > best_f1:
        best_f1 = f1
        best_model = model
        best_model_name = name

print(f"\nEn Başarılı Model: {best_model_name}")

print("\n3/4 SHAP (XAI) açıklayıcısı yapılandırılıyor...")
explainer = shap.TreeExplainer(best_model)

print("\n4/4 Varlıklar diske aktarılıyor...")
with open("best_model.pkl", "wb") as f:
    pickle.dump(best_model, f)

with open("shap_explainer.pkl", "wb") as f:
    pickle.dump(explainer, f)

with open("feature_names.pkl", "wb") as f:
    pickle.dump(feature_cols, f)

with open("metrics.pkl", "wb") as f:
    pickle.dump(results, f)

print("\nİşlem Tamamlandı! Tüm paketler hazır.")