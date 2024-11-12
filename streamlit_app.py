import streamlit as st
import os
import requests
import magic

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt', 'csv'}
MAX_FILE_SIZE_MB = 5
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # Set this environment variable

# Check if file is allowed based on extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to scan file using VirusTotal API
def scan_file_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
    }
    with open(file_path, 'rb') as f:
        response = requests.post(url, headers=headers, files={'file': f})
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Streamlit UI
st.title("Secure File Upload with Virus Scanning")

# File uploader
uploaded_file = st.file_uploader("Choose a file", type=list(ALLOWED_EXTENSIONS))

if uploaded_file:
    # Save the uploaded file to the server temporarily
    file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # File size check
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if file_size_mb > MAX_FILE_SIZE_MB:
        st.error(f"File size exceeds {MAX_FILE_SIZE_MB}MB.")
        os.remove(file_path)
    elif allowed_file(uploaded_file.name):
        # Scan the file using VirusTotal API
        result = scan_file_virustotal(file_path)
        if result:
            malicious = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious == 0:
                st.success("File is safe!")
            else:
                st.error("Malicious file detected!")
        else:
            st.error("Error scanning file with VirusTotal.")
        # Clean up the file after scanning
        os.remove(file_path)
    else:
        st.error("Invalid file type. Allowed types: png, jpg, jpeg, pdf, txt, csv.")
