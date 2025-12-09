import streamlit as st
import joblib
import re
from feature_extraction import extract_features  # Importing your helper function

# --- CONFIGURATION ---
st.set_page_config(
    page_title="SentinelAI - Phishing Detector",
    page_icon="🛡️",
    layout="centered"
)

# --- LOAD MODELS ---
# We use @st.cache_resource so it doesn't reload the models every time you click a button
@st.cache_resource
def load_models():
    try:
        url_model = joblib.load('url_model.pkl')
        text_model = joblib.load('text_model.pkl')
        vectorizer = joblib.load('vectorizer.pkl')
        return url_model, text_model, vectorizer
    except FileNotFoundError:
        st.error("❌ Models not found! Please run the training scripts first.")
        return None, None, None

url_model, text_model, vectorizer = load_models()

# --- UI DESIGN ---
st.title("🛡️ SentinelAI")
st.markdown("""
    **AI-Powered Phishing Email & Malicious Link Detector** *Paste an email below to scan for social engineering and malicious links.*
""")
st.divider()

# Input Area
email_text = st.text_area("📧 Email Content", height=200, placeholder="Paste the suspicious email text here...")

if st.button("🔍 Analyze Email", type="primary"):
    if not email_text:
        st.warning("Please paste some text first.")
    else:
        st.markdown("### 📊 Analysis Report")
        
        # --- 1. TEXT ANALYSIS (Engine B) ---
        # Convert text to numbers
        text_features = vectorizer.transform([email_text])
        # Predict
        text_prediction = text_model.predict(text_features)[0]
        text_prob = text_model.predict_proba(text_features)[0][1] * 100

        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Content Analysis")
            if text_prediction == 1:
                st.error(f"⚠️ **PHISHING DETECTED**")
                st.write(f"Confidence: **{text_prob:.1f}%**")
                st.info("The language used matches known scam patterns (urgency, fear, or financial requests).")
            else:
                st.success(f"✅ **Legitimate**")
                st.write(f"Confidence: **{100 - text_prob:.1f}%**")
                st.write("The email content appears normal.")

        # --- 2. LINK ANALYSIS (Engine A) ---
        # Find all links in the text
        urls = re.findall(r'(https?://\S+)', email_text)
        
        malicious_links = []
        safe_links = []

        if urls:
            for url in urls:
                # Extract features using your helper function
                features = extract_features(url)
                # Predict
                pred = url_model.predict([features])[0]
                
                if pred == 1:
                    malicious_links.append(url)
                else:
                    safe_links.append(url)

        with col2:
            st.subheader("Link Analysis")
            if not urls:
                st.write("No links found in this email.")
            else:
                if malicious_links:
                    st.error(f"Found {len(malicious_links)} Malicious Links!")
                    for link in malicious_links:
                        st.write(f"🔴 `{link}`")
                
                if safe_links:
                    st.success(f"Found {len(safe_links)} Safe Links")
                    with st.expander("View Safe Links"):
                        for link in safe_links:
                            st.write(f"🟢 {link}")

        # --- 3. FINAL RECOMMENDATION ---
        st.divider()
        st.subheader("🛡️ Recommendation")
        
        if text_prediction == 1 or malicious_links:
            st.error("🚫 **DO NOT REPLY OR CLICK LINKS.** This email is highly likely to be a phishing attack.")
        else:
            st.success("✅ **SAFE TO PROCEED.** No obvious threats were detected.")