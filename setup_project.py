import os
import shutil
import re

base_dir = os.path.dirname(os.path.abspath(__file__))
frontend_dir = os.path.join(base_dir, 'frontend')
backend_dir = os.path.join(base_dir, 'backend')

# Create directories
os.makedirs(os.path.join(frontend_dir, 'static', 'url_scam'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'static', 'fake_qr'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'static', 'email'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'static', 'malware'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'templates'), exist_ok=True)
os.makedirs(backend_dir, exist_ok=True)
os.makedirs(os.path.join(backend_dir, 'ML_model'), exist_ok=True)

def copy_and_replace(src, dst, replacements):
    if os.path.exists(src):
        with open(src, 'r', encoding='utf-8') as f:
            content = f.read()
        for old, new in replacements:
            content = content.replace(old, new)
        with open(dst, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Copied and modified {src} to {dst}")

# Move templates with replacements
copy_and_replace(
    os.path.join(base_dir, 'url scam detection', 'templates', 'dashboard.html'),
    os.path.join(frontend_dir, 'templates', 'url_dashboard.html'),
    [("filename='style.css'", "filename='url_scam/style.css'"), ("filename='app.js'", "filename='url_scam/app.js'")]
)

copy_and_replace(
    os.path.join(base_dir, 'fakeQRcode Detection', 'templates', 'dashboard.html'),
    os.path.join(frontend_dir, 'templates', 'qr_dashboard.html'),
    [("filename='style.css'", "filename='fake_qr/style.css'"), ("filename='app.js'", "filename='fake_qr/app.js'")]
)

copy_and_replace(
    os.path.join(base_dir, 'Malware Detection', 'templates', 'index.html'),
    os.path.join(frontend_dir, 'templates', 'malware_dashboard.html'),
    [("filename='style.css'", "filename='malware/style.css'"), ("filename='app.js'", "filename='malware/app.js'"), ('action="/analyze"', 'action="/analyze_malware"')]
)

copy_and_replace(
    os.path.join(base_dir, 'Malware Detection', 'templates', 'result.html'),
    os.path.join(frontend_dir, 'templates', 'malware_result.html'),
    [("filename='style.css'", "filename='malware/style.css'"), ("filename='app.js'", "filename='malware/app.js'")]
)

copy_and_replace(
    os.path.join(base_dir, 'EmailPhishing', 'templates', 'index.html'),
    os.path.join(frontend_dir, 'templates', 'email_dashboard.html'),
    [("filename='style.css'", "filename='email/style.css'"), ("filename='script.js'", "filename='email/script.js'")]
)

# Move statics
def copy_dir_contents(src_dir, dst_dir):
    if os.path.exists(src_dir):
        for item in os.listdir(src_dir):
            src_path = os.path.join(src_dir, item)
            dst_path = os.path.join(dst_dir, item)
            if os.path.isdir(src_path):
                if not os.path.exists(dst_path):
                    os.makedirs(dst_path)
                copy_dir_contents(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
                print(f"Copied {item} to {dst_dir}")

copy_dir_contents(os.path.join(base_dir, 'url scam detection', 'static'), os.path.join(frontend_dir, 'static', 'url_scam'))
copy_dir_contents(os.path.join(base_dir, 'fakeQRcode Detection', 'static'), os.path.join(frontend_dir, 'static', 'fake_qr'))
copy_dir_contents(os.path.join(base_dir, 'EmailPhishing', 'static'), os.path.join(frontend_dir, 'static', 'email'))

# Fix JS API endpoints
copy_and_replace(
    os.path.join(base_dir, 'fakeQRcode Detection', 'static', 'app.js'),
    os.path.join(frontend_dir, 'static', 'fake_qr', 'app.js'),
    [('"/predict"', '"/predict_qr"')]
)
copy_and_replace(
    os.path.join(base_dir, 'EmailPhishing', 'static', 'script.js'),
    os.path.join(frontend_dir, 'static', 'email', 'script.js'),
    [('"/analyze"', '"/analyze_email"')]
)

# Copy necessary backend files
def copy_file(src, dst):
    if os.path.exists(src):
        shutil.copy2(src, dst)

copy_file(os.path.join(base_dir, 'url scam detection', 'phishing_model.pkl'), os.path.join(backend_dir, 'phishing_model.pkl'))
copy_file(os.path.join(base_dir, 'url scam detection', 'featureextraction.py'), os.path.join(backend_dir, 'featureextraction.py'))
copy_file(os.path.join(base_dir, 'url scam detection', 'explainability.py'), os.path.join(backend_dir, 'explainability.py'))

copy_file(os.path.join(base_dir, 'Malware Detection', 'ML_model', 'malwareclassifier-V2.pkl'), os.path.join(backend_dir, 'ML_model', 'malwareclassifier-V2.pkl'))
copy_file(os.path.join(base_dir, 'Malware Detection', 'feature_extraction.py'), os.path.join(backend_dir, 'feature_extraction_malware.py'))

copy_file(os.path.join(base_dir, 'EmailPhishing', 'knowledge_base.txt'), os.path.join(backend_dir, 'knowledge_base.txt'))
copy_file(os.path.join(base_dir, 'EmailPhishing', '.env'), os.path.join(backend_dir, '.env'))

# Copy fake QR db
copy_file(os.path.join(base_dir, 'fakeQRcode Detection', 'stats.db'), os.path.join(backend_dir, 'stats.db'))

print("Project setup complete. Run the backend using: cd backend && python app.py")
