import streamlit as st
import joblib
import re
import numpy as np
from urllib.parse import urlparse

# --- 1. INTERNAL HELPER FUNCTION (No separate file needed) ---
def extract_features(url):
    url = str(url)
    parsed = urlparse(url)
    return [
        len(url),
        url.count('.'),
        url.count('@'),
        url.count('-'),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == 'https' else 0
    ]

# --- 2. APP CONFIGURATION ---
st.set_page_config(page_title="SentinelAI", page_icon="🛡️")

st.title("🛡️ SentinelAI")
st.write("### AI-Powered Phishing Email Detector")

# --- 3. LOAD MODELS WITH FALLBACK ---
@st.cache_resource
def load_brain():
    try:
        # Load the models - Ensure these 3 files are in your GitHub repo!
        url_model = joblib.load('url_model.pkl')
        text_model = joblib.load('text_model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        return url_model, text_model, vectorizer
    except Exception as e:
        st.error(f"❌ Error loading models: {e}")
        return None, None, None

url_model, text_model, vectorizer = load_brain()

# --- 4. CHECK IF MODELS LOADED ---
if not url_model:
    st.warning("⚠️ Models not found. Please ensure 'url_model.pkl', 'text_model.pkl', and 'vectorizer.pkl' are uploaded to GitHub.")
    st.stop() 

# --- 5. THE INTERFACE ---
email_text = st.text_area("Paste Email Content:", height=200)

if st.button("Analyze Email"):
    if not email_text:
        st.warning("Please paste text first.")
    else:
        # A. Analyze Text
        try:
            text_features = vectorizer.transform([email_text])
            text_verdict = text_model.predict(text_features)[0]
            text_prob = text_model.predict_proba(text_features)[0][1] * 100
            
            # B. Analyze Links
            urls = re.findall(r'(https?://\S+)', email_text)
            bad_links = []
            
            for url in urls:
                feats = extract_features(url)
                # Reshape for single prediction
                feats_array = np.array([feats]) 
                if url_model.predict(feats_array)[0] == 1:
                    bad_links.append(url)

            # C. Show Results
            st.divider()
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Text Analysis")
                if text_verdict == 1:
                    st.error(f"❌ Phishing Content ({text_prob:.1f}%)")
                    st.write("Suspicious language detected.")
                else:
                    st.success(f"✅ Safe Content ({100-text_prob:.1f}%)")
                    st.write("Language looks normal.")

            with col2:
                st.subheader("Link Analysis")
                if bad_links:
                    st.error(f"❌ {len(bad_links)} Malicious Links")
                    for l in bad_links: st.code(l)
                elif urls:
                    st.success(f"✅ {len(urls)} Links Scanned - All Safe")
                else:
                    st.info("No links found.")
        except Exception as e:
            st.error(f"An error occurred during analysis: {e}")
