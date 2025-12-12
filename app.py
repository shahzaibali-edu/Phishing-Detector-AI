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
    
    # Improved IP check for the feature extractor too
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    has_ip = 1 if re.search(ip_pattern, url) else 0
    
    return [
        len(url), url.count('.'), url.count('@'), url.count('-'),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == 'https' else 0,
        has_ip 
    ]

# --- 3. INPUT VALIDATION LAYER ---
def is_valid_email_text(text):
    text = text.strip()
    if len(text) == 0:
        return False, "Empty input, Paste something to analyze."
    if len(text) < 20:
        return False, "Input is too short to be a valid email."
    if any(len(w) > 40 and 'http' not in w for w in words):
        return False, "Detected gibberish or non-human text."
    words = text.split()
    if len(words) < 3:
        return False, "Contains too few words. Please paste the full email body."
    
    return True, ""

# --- 4. THE BACKUP ENGINE (RULE-BASED) ---
def backup_text_scan(text):
    keywords = ['urgent', 'verify', 'suspended', 'immediately', 'close', 'bank', 'password', 'unauthorized', 'lock', 'action required']
    found = [k for k in keywords if k in text.lower()]
    if found:
        return 1, f"Contains panic words: {', '.join(found)}"
    return 0, "Language appears normal"

def backup_url_scan(url):
    reasons = []
    # FIX: Use Regex for IP detection here too
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): reasons.append("IP address masking")
    if url.count('.') > 3: reasons.append("Too many subdomains")
    if url.count('-') > 3: reasons.append("Too many dashes")
    if url.count('@') > 0: reasons.append("Contains '@' symbol")
    if len(url) > 75: reasons.append("URL is suspiciously long")
    
    if reasons:
        return 1, ", ".join(reasons)
    return 0, "Clean URL structure"

# --- 5. LOAD MODELS ---
@st.cache_resource
def load_brain():
    try:
        url_model = joblib.load('url_model.pkl')
        text_model = joblib.load('text_model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        return url_model, text_model, vectorizer
    except Exception:
        return None, None, None

url_model, text_model, vectorizer = load_brain()

# --- 6. MAIN INTERFACE ---
st.title("🛡️ SentinelAI")
st.write("### AI-Powered Phishing Detector")

# Status Indicator
if url_model:
    st.success("🟢 System Status: **AI MODELS LOADED**")
else:
    st.warning("🟡 System Status: **BACKUP MODE** (Running Rule-Based Logic)")

email_text = st.text_area("Paste Email Content:", height=200, placeholder="Paste the full email body here...")

if st.button("Analyze Email"):
    # --- STEP 0: SANITY CHECK ---
    is_valid, error_msg = is_valid_email_text(email_text)
    
    if not is_valid:
        st.warning(f"⚠️ **Invalid Input:** {error_msg}")
    else:
        st.divider()
        col1, col2 = st.columns(2)

        # --- A. ANALYZE TEXT ---
        if text_model:
            text_features = vectorizer.transform([email_text])
            is_phishing = text_model.predict(text_features)[0]
            confidence = text_model.predict_proba(text_features)[0][1] * 100
            reason = "Suspicious language patterns detected" if is_phishing else "Language appears normal"
        else:
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

        # --- B. ANALYZE LINKS (FIXED IP DETECTION) ---
        urls = re.findall(r'(https?://\S+)', email_text)
        bad_links = []
        safe_links = []
        
        for url in urls:
            domain = urlparse(url).netloc
            
            # 1. Whitelist Check
            if any(trusted in domain for trusted in WHITELIST):
                safe_links.append((url, "Trusted Domain"))
                continue

            # 2. Analysis
            if url_model:
                manual_fail = False
                reason = "AI Pattern Match (Suspicious Structure)" # Default AI reason

                # Check specific rules to give a BETTER reason
                # FIX: Use Regex to find REAL IP addresses
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                    manual_fail = True
                    reason = "IP Address Masking (Rule Violation)"
                elif url.count('.') > 3:
                    manual_fail = True
                    reason = "Too many subdomains (Rule Violation)"
                elif url.count('-') > 3:
                    manual_fail = True
                    reason = "Too many dashes / Typosquatting (Rule Violation)"
                elif url.count('@') > 0:
                    manual_fail = True
                    reason = "Contains '@' symbol (Rule Violation)"
                
                # Run AI Check
                feats = np.array([extract_features(url)])
                ai_fail = url_model.predict(feats)[0] == 1
                
                # If EITHER failed, append the SPECIFIC reason
                if manual_fail or ai_fail:
                    bad_links.append((url, reason)) 
                else:
                    safe_links.append((url, "AI Analysis Passed"))
            else:
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
                    st.caption(f"⚠️ {reason}") # Now this will show specific reasons!
            elif safe_links:
                st.success(f"✅ {len(safe_links)} Links Scanned - All Safe")
                with st.expander("View Safe Links"):
                    for url, reason in safe_links:
                        st.write(f"🟢 {url}")
                        st.caption(f"Reason: {reason}")
            else:
                st.info("No links found.")

