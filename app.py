import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import matplotlib.pyplot as plt

# Set page configuration
st.set_page_config(page_title="AI Cyber Threat Detector", layout="wide")

# ----------------------------------------------------
# 1. Synthetic Data Generation (For Demonstration)
# ----------------------------------------------------
@st.cache_data
def generate_synthetic_data(n_samples=1000):
    np.random.seed(42)
    
    # Features: duration (sec), packet_count, bytes_transferred, failed_login_attempts
    # Let's generate normal traffic
    normal_duration = np.random.exponential(scale=5, size=int(n_samples * 0.8))
    normal_packets = np.random.poisson(lam=50, size=int(n_samples * 0.8))
    normal_bytes = normal_packets * np.random.normal(loc=500, scale=100, size=int(n_samples * 0.8))
    normal_failed_logins = np.random.binomial(n=1, p=0.05, size=int(n_samples * 0.8))
    normal_labels = np.zeros(int(n_samples * 0.8)) # 0 = Benign

    # Let's generate malicious traffic (e.g., high failed logins, massive packet volume, or long unusual connections)
    malicious_duration = np.random.uniform(low=10, high=300, size=int(n_samples * 0.2))
    malicious_packets = np.random.poisson(lam=500, size=int(n_samples * 0.2))
    malicious_bytes = malicious_packets * np.random.normal(loc=1200, scale=300, size=int(n_samples * 0.2))
    malicious_failed_logins = np.random.randint(low=3, high=15, size=int(n_samples * 0.2))
    malicious_labels = np.ones(int(n_samples * 0.2)) # 1 = Threat

    # Combine into a single DataFrame
    df = pd.DataFrame({
        'Duration_Sec': np.concatenate([normal_duration, malicious_duration]),
        'Packet_Count': np.concatenate([normal_packets, malicious_packets]),
        'Bytes_Transferred': np.concatenate([normal_bytes, malicious_bytes]),
        'Failed_Login_Attempts': np.concatenate([normal_failed_logins, malicious_failed_logins]),
        'Label': np.concatenate([normal_labels, malicious_labels])
    })
    
    # Shuffle dataset
    df = df.sample(frac=1).reset_index(drop=True)
    return df

# ----------------------------------------------------
# 2. Model Training
# ----------------------------------------------------
@st.cache_resource
def train_model(df):
    X = df[['Duration_Sec', 'Packet_Count', 'Bytes_Transferred', 'Failed_Login_Attempts']]
    y = df['Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)
    
    # Calculate simple evaluation metrics
    predictions = model.predict(X_test)
    acc = accuracy_score(y_test, predictions)
    
    return model, acc

# Load and train
df_data = generate_synthetic_data()
model, accuracy = train_model(df_data)

# ----------------------------------------------------
# 3. Streamlit UI Layout
# ----------------------------------------------------
st.title("🛡️ AI-Based Cyber Threat Detection Framework")
st.write(
    "This prototype demonstrates how machine learning models can assist in analyzing network logs "
    "to identify potential security threats. It uses a Random Forest classifier trained on simulated network activity."
)

# Sidebar with Model Info and Feature Importance
st.sidebar.header("Model Diagnostics")
st.sidebar.write(f"**Model Accuracy on Test Set:** {accuracy * 100:.2f}%")

# Feature Importance Plot
importances = model.feature_importances_
features = ['Duration (s)', 'Packet Count', 'Bytes Transferred', 'Failed Logins']
fig, ax = plt.subplots(figsize=(4, 3))
ax.barh(features, importances, color='#1f77b4')
ax.set_title("Feature Importance")
plt.tight_layout()
st.sidebar.pyplot(fig)

# Interactive Tabs
tab1, tab2 = st.tabs(["🔍 Live Threat Analyzer", "📁 Batch Processing (CSV)"])

# TAB 1: Live Manual Input
with tab1:
    st.subheader("Manual Traffic Simulation")
    st.write("Adjust the parameters below to simulate real-time network traffic and evaluate risk.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        duration = st.slider("Connection Duration (seconds)", min_value=0.1, max_value=600.0, value=5.0, step=0.5)
        packet_count = st.number_input("Packet Count", min_value=1, max_value=10000, value=45)
        
    with col2:
        bytes_transferred = st.number_input("Bytes Transferred", min_value=0, max_value=10000000, value=25000)
        failed_logins = st.slider("Failed Login Attempts", min_value=0, max_value=20, value=0)

    # Prediction Trigger
    if st.button("Analyze Flow"):
        # Make prediction
        input_data = pd.DataFrame([[duration, packet_count, bytes_transferred, failed_logins]], 
                                  columns=['Duration_Sec', 'Packet_Count', 'Bytes_Transferred', 'Failed_Login_Attempts'])
        prediction = model.predict(input_data)[0]
        prediction_proba = model.predict_proba(input_data)[0]
        
        # Display Result
        st.write("---")
        if prediction == 1:
            st.error(f"🚨 **Threat Detected!** (Confidence: {prediction_proba[1]*100:.2f}%)")
            st.write(
                "**Potential Threat Type:** Anomalous network burst or credential brute-force attempt. "
                "Review the failed login count and connection duration."
            )
        else:
            st.success(f"✅ **Traffic Appears Benign** (Confidence: {prediction_proba[0]*100:.2f}%)")
            st.write("The evaluated connection profiles fit normal baseline thresholds.")

# TAB 2: Batch Processing Demo
with tab2:
    st.subheader("Batch Analysis via CSV Upload")
    st.write("Upload a dataset containing network logs to flag anomalies in bulk.")
    
    # Download template button
    template_df = pd.DataFrame({
        'Duration_Sec': [2.5, 120.0, 1.2],
        'Packet_Count': [35, 800, 15],
        'Bytes_Transferred': [15000, 950000, 5000],
        'Failed_Login_Attempts': [0, 8, 1]
    })
    
    @st.cache_data
    def convert_df(df):
        return df.to_csv(index=False).encode('utf-8')
        
    csv_template = convert_df(template_df)
    
    st.download_button(
        label="Download Sample Template CSV",
        data=csv_template,
        file_name="network_traffic_sample.csv",
        mime="text/csv",
    )
    
    uploaded_file = st.file_uploader("Upload your network log CSV here", type=["csv"])
    
    if uploaded_file is not None:
        try:
            uploaded_df = pd.read_csv(uploaded_file)
            
            # Check for required columns
            required_cols = ['Duration_Sec', 'Packet_Count', 'Bytes_Transferred', 'Failed_Login_Attempts']
            if not all(col in uploaded_df.columns for col in required_cols):
                st.error(f"The uploaded CSV must contain the following columns: {required_cols}")
            else:
                # Run predictions
                features_to_predict = uploaded_df[required_cols]
                predictions = model.predict(features_to_predict)
                probabilities = model.predict_proba(features_to_predict)[:, 1]
                
                # Append findings
                uploaded_df['Threat_Assessment'] = np.where(predictions == 1, '🚨 Threat Found', '✅ Benign')
                uploaded_df['Threat_Probability (%)'] = np.round(probabilities * 100, 2)
                
                # Display Summary Metrics
                threat_count = int((predictions == 1).sum())
                st.metric(label="Total Log Entries Analyzed", value=len(uploaded_df))
                st.metric(label="Suspected Threats Blocked/Flagged", value=threat_count, delta=f"{threat_count} flagged", delta_color="inverse")
                
                # Show results table
                st.dataframe(uploaded_df)
                
        except Exception as e:
            st.error(f"An error occurred while parsing the file: {e}")