import os
import sqlite3
import joblib
import numpy as np
import PyPDF2
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

# Feature extractions
from featureextraction import extract_features as extract_features_url
from feature_extraction_malware import extract_features as extract_features_malware
from explainability import PhishingExplainer

# Langchain / Gemini for Email Phishing
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_classic.chains import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate

load_dotenv()

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
CORS(app)

# -----------------------------
# 1. URL & QR Code Scam Detection Setup
# -----------------------------
phishing_model = joblib.load("phishing_model.pkl")
feature_names = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]
explainer = PhishingExplainer(phishing_model, feature_names)

DB_PATH = 'stats.db'
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            visitors INTEGER DEFAULT 0,
            scans INTEGER DEFAULT 0,
            phishing INTEGER DEFAULT 0,
            legitimate INTEGER DEFAULT 0,
            medium INTEGER DEFAULT 0
        )
    ''')
    c.execute('INSERT OR IGNORE INTO stats (id, visitors, scans, phishing, legitimate, medium) VALUES (1, 0, 0, 0, 0, 0)')
    conn.commit()
    conn.close()

init_db()

def increment_stat(column):
    valid_columns = ['visitors', 'scans', 'phishing', 'legitimate', 'medium']
    if column in valid_columns:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(f'UPDATE stats SET {column} = {column} + 1 WHERE id = 1')
        conn.commit()
        conn.close()

# -----------------------------
# 2. Malware Detection Setup
# -----------------------------
malware_model = joblib.load('ML_model/malwareclassifier-V2.pkl')
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'dll', 'exe'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------------
# 3. Email Phishing Setup
# -----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
rag_chain = None
rag_error = None

if GEMINI_API_KEY:
    llm = ChatGoogleGenerativeAI(model="gemini-3.5-flash", google_api_key=GEMINI_API_KEY, temperature=0.1)
    embeddings = GoogleGenerativeAIEmbeddings(model="models/gemini-embedding-2", google_api_key=GEMINI_API_KEY)

    try:
        loader = TextLoader("knowledge_base.txt")
        docs = loader.load()
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=100)
        splits = text_splitter.split_documents(docs)
        vectorstore = FAISS.from_documents(documents=splits, embedding=embeddings)
        retriever = vectorstore.as_retriever()
        
        system_prompt = (
            "You are an expert cybersecurity analyst specialized in detecting email phishing attempts. "
            "Use the following retrieved context to analyze the provided email content. "
            "Determine if the email is 'Phishing' or 'Safe'. Provide a detailed reasoning based on the context and indicators present. "
            "Point out specific red flags (if any) such as urgent language, suspicious links, or weird sender domains. "
            "Also, estimate the probability (0 to 100) that this email is phishing based on the severity of the indicators. "
            "Format your response in a clear and structured way using Markdown.\n\n"
            "IMPORTANT: You MUST start your response exactly with the following HTML block to highlight the final verdict and probability. "
            "Use <div class='verdict verdict-safe' data-probability='[PROBABILITY]'>SAFE</div> if safe, or <div class='verdict verdict-phishing' data-probability='[PROBABILITY]'>PHISHING</div> if it is phishing. Replace [PROBABILITY] with the integer percentage chance (e.g. 15 for 15%).\n\n"
            "{context}"
        )
        prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", "{input}")])
        question_answer_chain = create_stuff_documents_chain(llm, prompt)
        rag_chain = create_retrieval_chain(retriever, question_answer_chain)
    except Exception as e:
        rag_error = str(e)
else:
    rag_error = "GEMINI_API_KEY is not set."

# -----------------------------
# Unified Routes
# -----------------------------

@app.route("/")
def home():
    # Render the unified home page
    return render_template("home.html")

# --- URL Scam Routes ---
@app.route("/url_scam")
def url_scam_home():
    return render_template("url_dashboard.html")

@app.route("/predict", methods=["POST"])
def predict_url():
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "URL not provided"}), 400
        url = data["url"].strip()
        if not url:
            return jsonify({"error": "URL not provided"}), 400
            
        features = extract_features_url(url)
        features_array = np.array([[features[name] for name in feature_names]], dtype=float)
        prediction = int(phishing_model.predict(features_array)[0])
        probability = phishing_model.predict_proba(features_array)[0]
        threat_level = float(round(probability[1] * 100, 2))
        explanation = explainer.explain(features_array)
        
        if threat_level >= 70: result = "Phishing"
        elif threat_level >= 30: result = "Medium Legitimate"
        else: result = "Legitimate"

        return jsonify({
            "url": url,
            "prediction": result,
            "threat_level": threat_level,
            "features": features,
            "explanation": explanation
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Fake QR Code Routes ---
@app.route("/qr_scan")
def qr_scan_home():
    increment_stat('visitors')
    return render_template("qr_dashboard.html")

@app.route("/predict_qr", methods=["POST"])
def predict_qr():
    try:
        data = request.get_json()
        if not data or "url" not in data:
            return jsonify({"error": "URL not provided"}), 400
        url = data["url"].strip()
        if not url:
            return jsonify({"error": "URL not provided"}), 400
            
        features = extract_features_url(url)
        features_array = np.array([[features[name] for name in feature_names]], dtype=float)
        prediction = int(phishing_model.predict(features_array)[0])
        probability = phishing_model.predict_proba(features_array)[0]
        threat_level = float(round(probability[1] * 100, 2))
        explanation = explainer.explain(features_array)
        
        if threat_level >= 70:
            result = "Phishing"
            increment_stat('phishing')
        elif threat_level >= 30:
            result = "Medium Legitimate"
            increment_stat('medium')
        else:
            result = "Legitimate"
            increment_stat('legitimate')

        increment_stat('scans')

        return jsonify({
            "url": url,
            "prediction": result,
            "threat_level": threat_level,
            "features": features,
            "explanation": explanation
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Malware Detection Routes ---
@app.route("/malware")
def malware_home():
    return render_template("malware_dashboard.html")

@app.route('/analyze_malware', methods=['POST'])
def analyze_malware():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            return render_template('malware_dashboard.html', error="Unsupported file type.")
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        features = extract_features_malware(file_path)
        if features is not None:
            prediction = malware_model.predict(features)
            result = {
                "type": "file",
                "prediction": "Malware" if prediction[0] == 1 else "Safe",
                "file_name": file.filename
            }
        else:
            result = {
                "type": "file",
                "prediction": "Error: Invalid PE file format",
                "file_name": file.filename
            }
        if os.path.exists(file_path):
            os.remove(file_path)
        return render_template('malware_result.html', result=result)
    return render_template('malware_dashboard.html', error="No file uploaded.")

# --- Email Phishing Routes ---
@app.route("/email_phishing")
def email_phishing_home():
    return render_template("email_dashboard.html")

@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    if not rag_chain:
        return jsonify({"error": f"The RAG system failed to initialize. Exact Error: {rag_error}"}), 500
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and file.filename.lower().endswith('.pdf'):
        try:
            pdf_reader = PyPDF2.PdfReader(file)
            email_text = ""
            for page in pdf_reader.pages:
                extracted = page.extract_text()
                if extracted: email_text += extracted + "\n"
            if not email_text.strip():
                return jsonify({"error": "Could not extract text from the PDF"}), 400
            
            response = rag_chain.invoke({"input": email_text})
            return jsonify({"result": response["answer"]})
        except Exception as e:
            return jsonify({"error": f"Failed to process PDF: {str(e)}"}), 500
    else:
        return jsonify({"error": "Only PDF files are allowed"}), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)
