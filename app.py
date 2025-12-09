import streamlit as st
import joblib
import re
import numpy as np
import os
from urllib.parse import urlparse

# --- 0. DIAGNOSTIC SETUP ---
st.set_page_config(page_title="SentinelAI", page_icon="🛡️")

# --- 1. CONFIGURATION & WHITELIST ---
WHITELIST = ['zoom.us', 'google.com', 'microsoft.com', 'outlook.com', 'paypal.com', 'netflix.com', 'drive.google.com']

# --- 2. INTELLIGENT HELPER FUNCTIONS ---
def extract_features(url):
    url = str(url)
    parsed = urlparse(url)
    return [
        len(url), url.count('.'), url.count('@'), url.count('-'),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == 'https' else 0,
        1 if 'ip' in url.lower() else 0
    ]

def get_link_reason(url):
    reasons = []
    # 1. Rule-Based Triggers (The "Obvious" stuff)
    if 'ip' in url.lower(): return "IP address masking (High Risk)"
    if url.count('.') > 3: return "Too many subdomains (Suspicious)"
    if url.count('-') > 3: return "Too many dashes (Typosquatting)"
    if url.count('@') > 0: return "Contains '@' symbol"
    
    # 2. AI-Based Triggers (The "Subtle" stuff)
    if len(url) > 75: reasons.append("Abnormally long URL")
    if sum(c.isdigit() for c in url) > 5: reasons.append("High digit count")
    
    return ", ".join(reasons) if reasons else "AI Pattern Match"

def get_text_reason(text):
    triggers = []
    keywords = ['urgent', 'verify', 'suspended', 'immediately', 'close', 'bank', 'password', 'unauthorized', 'lock']
    for k in keywords:
        if k in text.lower(): triggers.append(k)
    return f"Contains panic words: {', '.join(triggers)}" if triggers else "Suspicious sentence structure"

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
    st.error("⚠️ Models not found. Please upload .pkl files to GitHub.")
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
                st.write("**Why?** Language appears normal.")

        # --- B. ANALYZE LINKS (HYBRID ENGINE) ---
        urls = re.findall(r'(https?://\S+)', email_text)
        bad_links = []
        safe_links = []
        
        for url in urls:
            domain = urlparse(url).netloc
            
            # 1. Whitelist Check (Pass safe stuff immediately)
            if any(trusted in domain for trusted in WHITELIST):
                safe_links.append((url, "Trusted Domain"))
                continue

            # 2. Rule-Based Check (Catch obviously bad stuff)
            # If it has an IP, >3 dots, or >3 dashes, FAIL IT IMMEDIATELY.
            manual_fail = False
            if 'ip' in url.lower() or url.count('.') > 3 or url.count('-') > 3:
                manual_fail = True

            # 3. AI Check (Catch the rest)
            feats = np.array([extract_features(url)])
            ai_fail = url_model.predict(feats)[0] == 1

            # Final Verdict: If EITHER the Rules OR the AI say it's bad, it's bad.
            if manual_fail or ai_fail:
                bad_links.append((url, get_link_reason(url)))
            else:
                safe_links.append((url, "AI Analysis Passed"))

        with col2:
            st.subheader("🔗 Link Analysis")
            if bad_links:
                st.error(f"❌ Found {len(bad_links)} Malicious Links")
                for url, reason in bad_links:
                    st.code(url)
                    st.caption(f"⚠️ {reason}")
            elif safe_links:
                st.success(f"✅ {len(safe_links)} Links Scanned - All Safe")
                with st.expander("View Safe Links"):
                    for url, reason in safe_links:
                        st.write(f"🟢 {url}")
                        st.caption(f"Reason: {reason}")
            else:
                st.info("No links found.")
