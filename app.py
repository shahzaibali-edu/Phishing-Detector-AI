import streamlit as st
import joblib
import re
import numpy as np
import os
from urllib.parse import urlparse

# --- DEBUGGING: PRINT FILES ---
st.write("### 📂 Server File Debugger")
st.write(f"Current Working Directory: `{os.getcwd()}`")
st.write("Files in this directory:")
st.write(os.listdir('.')) # This prints the list of files the app can actually see
st.divider()

# --- 1. INTERNAL HELPER FUNCTION ---
def extract_features(url):
    url = str(url)
    parsed = urlparse(url)
    return [
        len(url), url.count('.'), url.count('@'), url.count('-'),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == 'https' else 0,
        1 if 'ip' in url.lower() else 0
    ]

# --- 2. CONFIG ---
st.set_page_config(page_title="SentinelAI", page_icon="🛡️")
st.title("🛡️ SentinelAI")

# --- 3. LOAD MODELS ---
@st.cache_resource
def load_brain():
    try:
        # We look for the files. If they are in a folder, we might need to add the folder name.
        url_model = joblib.load('url_model.pkl')
        text_model = joblib.load('text_model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        return url_model, text_model, vectorizer
    except Exception as e:
        st.error(f"❌ Error Detail: {e}")
        return None, None, None

url_model, text_model, vectorizer = load_brain()

# --- 4. CHECK IF MODELS LOADED ---
if not url_model:
    st.warning("⚠️ App stopped because models failed to load.")
    st.stop()

# --- 5. INTERFACE ---
email_text = st.text_area("Paste Email Content:", height=200)

if st.button("Analyze Email"):
    if not email_text:
        st.warning("Please paste text first.")
    else:
        # A. Analyze Text
        text_features = vectorizer.transform([email_text])
        text_verdict = text_model.predict(text_features)[0]
        text_prob = text_model.predict_proba(text_features)[0][1] * 100
        
        # B. Analyze Links
        urls = re.findall(r'(https?://\S+)', email_text)
        bad_links = []
        for url in urls:
            feats = np.array([extract_features(url)])
            if url_model.predict(feats)[0] == 1:
                bad_links.append(url)

        # C. Results
        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            if text_verdict == 1:
                st.error(f"❌ Phishing Content ({text_prob:.1f}%)")
            else:
                st.success(f"✅ Safe Content ({100-text_prob:.1f}%)")
        with col2:
            if bad_links:
                st.error(f"❌ {len(bad_links)} Malicious Links")
            else:
                st.success(f"✅ Links Safe")
