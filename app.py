import streamlit as st
import joblib
import re
import numpy as np
import os
from urllib.parse import urlparse

# --- 0. SETUP ---
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

# --- 3. THE BACKUP ENGINE (RULE-BASED) ---
# This runs if the AI models are missing. It mimics the AI's logic.
def backup_text_scan(text):
    keywords = ['urgent', 'verify', 'suspended', 'immediately', 'close', 'bank', 'password', 'unauthorized', 'lock', 'action required']
    found = [k for k in keywords if k in text.lower()]
    if found:
        return 1, f"Contains panic words: {', '.join(found)}"
    return 0, "Language appears normal"

def backup_url_scan(url):
    reasons = []
    if 'ip' in url.lower(): reasons.append("IP address masking")
    if url.count('.') > 3: reasons.append("Too many subdomains")
    if url.count('-') > 3: reasons.append("Too many dashes")
    if url.count('@') > 0: reasons.append("Contains '@' symbol")
    if len(url) > 75: reasons.append("URL is suspiciously long")
    
    if reasons:
        return 1, ", ".join(reasons)
    return 0, "Clean URL structure"

# --- 4. LOAD MODELS (WITH SAFE FAILOVER) ---
@st.cache_resource
def load_brain():
    try:
        url_model = joblib.load('url_model.pkl')
        text_model = joblib.load('text_model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        return url_model, text_model, vectorizer
    except Exception:
        # If files are missing, return NONE. The app will handle this gracefully.
        return None, None, None

url_model, text_model, vectorizer = load_brain()

# --- 5. MAIN INTERFACE ---
st.title("🛡️ SentinelAI")
st.write("### AI-Powered Phishing Detector")

# Status Indicator
if url_model:
    st.success("🟢 System Status: **AI MODELS LOADED**")
else:
    st.warning("🟡 System Status: **BACKUP MODE** (Running Rule-Based Logic)")

email_text = st.text_area("Paste Email Content:", height=200)

if st.button("Analyze Email"):
    if not email_text:
        st.warning("Please paste text first.")
    else:
        st.divider()
        col1, col2 = st.columns(2)

        # --- A. ANALYZE TEXT ---
        if text_model:
            # Use AI if available
            text_features = vectorizer.transform([email_text])
            is_phishing = text_model.predict(text_features)[0]
            confidence = text_model.predict_proba(text_features)[0][1] * 100
            reason = "Suspicious language patterns detected" if is_phishing else "Language appears normal"
        else:
            # Use Backup if AI is missing
            is_phishing, reason = backup_text_scan(email_text)
            confidence = 95.0 if is_phishing else 5.0

        with col1:
            st.subheader("📝 Content Analysis")
            if is_phishing:
                st.error(f"❌ Phishing Detected ({confidence:.1f}%)")
                st.write(f"**Why?** {reason}")
            else:
                st.success(f"✅ Content Safe ({100-confidence:.1f}%)")
                st.write(f"**Why?** {reason}")

        # --- B. ANALYZE LINKS ---
        urls = re.findall(r'(https?://\S+)', email_text)
        bad_links = []
        safe_links = []
        
        for url in urls:
            domain = urlparse(url).netloc
            
            # 1. Whitelist Check
            if any(trusted in domain for trusted in WHITELIST):
                safe_links.append((url, "Trusted Domain"))
                continue

            # 2. Analysis (AI or Backup)
            if url_model:
                # Hybrid: Rules First, then AI
                manual_fail = False
                if 'ip' in url.lower() or url.count('.') > 3 or url.count('-') > 3:
                    manual_fail = True
                    reason = "Suspicious Pattern (Rules)"
                
                feats = np.array([extract_features(url)])
                ai_fail = url_model.predict(feats)[0] == 1
                
                if manual_fail or ai_fail:
                    bad_links.append((url, "Malicious Link Detected"))
                else:
                    safe_links.append((url, "AI Analysis Passed"))
            else:
                # Backup Mode
                is_bad, reason = backup_url_scan(url)
                if is_bad:
                    bad_links.append((url, reason))
                else:
                    safe_links.append((url, "Link Structure Clean"))

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
