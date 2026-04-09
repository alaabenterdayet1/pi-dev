import json
import pandas as pd
import numpy as np
from pandas import json_normalize
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
from scipy.stats.mstats import winsorize

with open("dataset1_classification_noisy.json", "r") as file:
    data = json.load(file)

df = json_normalize(data)

numeric_cols = df.select_dtypes(include='number').columns
for col in numeric_cols:
    df[col] = df[col].fillna(df[col].mean())

categorical_cols = df.select_dtypes(include='object').columns
for col in categorical_cols:
    df[col] = df[col].fillna(df[col].mode()[0])

df2 = df.copy()
categorical_cols = ["log_program", "decoder_name", "cortex_taxonomies", "fw_interface", "iris_severity_name"]
for col in categorical_cols:
    le = LabelEncoder()
    df2[col] = le.fit_transform(df2[col])

df2 = pd.get_dummies(df2, columns=['fw_action_type'], prefix='fw_action_type')

df3 = df2.drop(columns=["rule_description", "vt_tags", "log_location"])

features = ['rule_id', 'rule_level', 'fired_times', 'src_port', 'log_program',
            'decoder_name', 'vt_reputation', 'vt_malicious', 'vt_suspicious',
            'vt_undetected', 'cortex_taxonomies', 'iris_severity_id',
            'iris_severity_name', 'fw_interface']
df_numbers = df3[features]

scaler = StandardScaler()
df_scaled = scaler.fit_transform(df_numbers)

outlier_cols = ['fired_times', 'rule_level', 'vt_malicious', 'vt_reputation', 'vt_suspicious']
df_clean = df3.copy()
for col in outlier_cols:
    df_clean[col] = winsorize(df_clean[col], limits=[0.01, 0.01])

df_model = df_clean.copy()
for col in df_model.select_dtypes(include='object'):
    df_model[col] = df_model[col].astype('category')

y = df_model['iris_severity_name']
X = df_model.drop(columns=['iris_severity_name'], errors='ignore')

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = XGBClassifier(
    n_estimators=400,
    max_depth=3,
    learning_rate=0.03,
    random_state=42,
    use_label_encoder=False,
    eval_metric='mlogloss',
    enable_categorical=True
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))