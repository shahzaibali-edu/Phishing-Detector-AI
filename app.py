import streamlit as st
import joblib
import re
import numpy as np
from urllib.parse import urlparse

# --- 1. CONFIGURATION & WHITELIST ---
st.set_page_config(page_title="SentinelAI", page_icon="🛡️")

# Trusted domains that we should NEVER flag as phishing
WHITELIST = ['zoom.us', 'google.com', 'microsoft.com', 'outlook.com', 'paypal.com', 'netflix.com']

# --- 2. INTELLIGENT HELPER FUNCTIONS ---
def extract_features(url):
    url = str(url)
    parsed = urlparse(url)
    return [
        len(url),                            # Length
        url.count('.'),                      # Dot count
        url.count('@'),                      # @ symbol
        url.count('-'),                      # Dash count
        sum(c.isdigit() for c in url),       # Number count
        1 if parsed.scheme == 'https' else 0, # HTTPS check
        1 if 'ip' in url.lower() else 0       # IP check
    ]

def get_link_reason(url):
    # This function explains WHY a link is considered bad
    reasons = []
    if len(url) > 75: reasons.append("URL is suspiciously long")
    if url.count('-') > 3: reasons.append("Too many dashes (typosquatting)")
    if url.count('@') > 0: reasons.append("Contains '@' (credential harvesting)")
    if url.count('.') > 5: reasons.append("Too many subdomains")
    if sum(c.isdigit() for c in url) > 5: reasons.append("High number of digits")
    if 'ip' in url.lower(): reasons.append("IP address masking")
    
    return ", ".join(reasons) if reasons else "Pattern matches known phishing links"

def get_text_reason(text):
    # Simple keyword search to explain text flags
    triggers = []
    keywords = ['urgent', 'verify', 'suspended', 'immediately', 'close', 'bank', 'password']
    for k in keywords:
        if k in text.lower():
            triggers.append(k)
    return f"Contains panic words: {', '.join(triggers)}" if triggers else "Suspicious sentence structure detected"

# --- 3. LOAD MODELS ---
@st.cache_resource
def load_brain():
    try:
        url_model = joblib.load('url_model.pkl')
        text_model = joblib.load('text_model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        return url_model, text_model, vectorizer
    except Exception as e:
        return None, None, None

url_model, text_model, vectorizer = load_brain()

# --- 4. MAIN INTERFACE ---
st.title("🛡️ SentinelAI")
st.write("### AI-Powered Phishing Detector")

if not url_model:
    st.error("⚠️ Models not found on GitHub! Please upload the .pkl files.")
    st.stop()

email_text = st.text_area("Paste Email Content:", height=200)

if st.button("Analyze Email"):
    if not email_text:
        st.warning("Please paste text first.")
    else:
        st.divider()
        col1, col2 = st.columns(2)

        # --- A. ANALYZE TEXT ---
        text_features = vectorizer.transform([email_text])
        text_verdict = text_model.predict(text_features)[0]
        text_prob = text_model.predict_proba(text_features)[0][1] * 100

        with col1:
            st.subheader("📝 Content Analysis")
            if text_verdict == 1:
                st.error(f"❌ Phishing Detected ({text_prob:.1f}%)")
                st.write(f"**Why?** {get_text_reason(email_text)}")
            else:
                st.success(f"✅ Content Safe ({100-text_prob:.1f}%)")
                st.write("**Why?** Language appears normal and professional.")

        # --- B. ANALYZE LINKS ---
        urls = re.findall(r'(https?://\S+)', email_text)
        bad_links = []
        safe_links = []
        
        for url in urls:
            # Check Whitelist First
            domain = urlparse(url).netloc
            if any(trusted in domain for trusted in WHITELIST):
                safe_links.append((url, "Trusted Domain (Whitelisted)"))
                continue

            # Run AI Model
            feats = np.array([extract_features(url)])
            if url_model.predict(feats)[0] == 1:
                reason = get_link_reason(url)
                bad_links.append((url, reason))
            else:
                safe_links.append((url, "AI Analysis Passed"))

        with col2:
            st.subheader("🔗 Link Analysis")
            if bad_links:
                st.error(f"❌ Found {len(bad_links)} Malicious Links")
                for url, reason in bad_links:
                    st.code(url)
                    st.caption(f"⚠️ **Reason:** {reason}")
            elif safe_links:
                st.success(f"✅ {len(safe_links)} Links Scanned - All Safe")
                with st.expander("View Safe Links"):
                    for url, reason in safe_links:
                        st.write(f"🟢 {url}")
                        st.caption(f"Reason: {reason}")
            else:
                st.info("No links found.")
