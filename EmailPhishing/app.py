import os
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_classic.chains import create_retrieval_chain
from langchain_classic.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate
import PyPDF2
# Load environment variables (such as GEMINI_API_KEY)
load_dotenv()

app = Flask(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("Warning: GEMINI_API_KEY is not set. Please create a .env file and set GEMINI_API_KEY.")

# Initialize the LLM and Embeddings model using Gemini
llm = ChatGoogleGenerativeAI(
    model="gemini-3.5-flash",
    google_api_key=GEMINI_API_KEY,
    temperature=0.1
)

embeddings = GoogleGenerativeAIEmbeddings(
    model="models/gemini-embedding-2",
    google_api_key=GEMINI_API_KEY
)

rag_error = None

def setup_rag():
    global rag_error
    try:
        # Load the knowledge base
        loader = TextLoader("knowledge_base.txt")
        docs = loader.load()
        
        # Split text into chunks
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=100)
        splits = text_splitter.split_documents(docs)
        
        # Create Vector Store
        vectorstore = FAISS.from_documents(documents=splits, embedding=embeddings)
        retriever = vectorstore.as_retriever()
        
        # Define the system prompt for RAG
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
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", "{input}"),
        ])
        
        # Create the chains
        question_answer_chain = create_stuff_documents_chain(llm, prompt)
        rag_chain = create_retrieval_chain(retriever, question_answer_chain)
        return rag_chain
    except Exception as e:
        print(f"Failed to initialize RAG: {e}")
        rag_error = str(e)
        return None

rag_chain = setup_rag()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
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
                if extracted:
                    email_text += extracted + "\n"
            
            if not email_text.strip():
                return jsonify({"error": "Could not extract text from the PDF"}), 400

            # Invoke the RAG chain with the extracted email content
            response = rag_chain.invoke({"input": email_text})
            return jsonify({"result": response["answer"]})
        except Exception as e:
            return jsonify({"error": f"Failed to process PDF: {str(e)}"}), 500
    else:
        return jsonify({"error": "Only PDF files are allowed"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
