import os
import shutil

base_dir = '/home/deongeorge/Downloads/SINGHAM'
frontend_dir = os.path.join(base_dir, 'frontend')
backend_dir = os.path.join(base_dir, 'backend')

# Create directories
os.makedirs(os.path.join(frontend_dir, 'static', 'url_scam'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'static', 'fake_qr'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'static', 'email'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'static', 'malware'), exist_ok=True)
os.makedirs(os.path.join(frontend_dir, 'templates'), exist_ok=True)
os.makedirs(backend_dir, exist_ok=True)

def move_file(src, dst):
    if os.path.exists(src):
        shutil.move(src, dst)

# Move templates
move_file(os.path.join(base_dir, 'url scam detection', 'templates', 'dashboard.html'), os.path.join(frontend_dir, 'templates', 'url_dashboard.html'))
move_file(os.path.join(base_dir, 'fakeQRcode Detection', 'templates', 'dashboard.html'), os.path.join(frontend_dir, 'templates', 'qr_dashboard.html'))
move_file(os.path.join(base_dir, 'Malware Detection', 'templates', 'index.html'), os.path.join(frontend_dir, 'templates', 'malware_dashboard.html'))
move_file(os.path.join(base_dir, 'Malware Detection', 'templates', 'result.html'), os.path.join(frontend_dir, 'templates', 'malware_result.html'))
move_file(os.path.join(base_dir, 'EmailPhishing', 'templates', 'index.html'), os.path.join(frontend_dir, 'templates', 'email_dashboard.html'))

# Move statics
def move_dir_contents(src_dir, dst_dir):
    if os.path.exists(src_dir):
        for item in os.listdir(src_dir):
            shutil.move(os.path.join(src_dir, item), os.path.join(dst_dir, item))

move_dir_contents(os.path.join(base_dir, 'url scam detection', 'static'), os.path.join(frontend_dir, 'static', 'url_scam'))
move_dir_contents(os.path.join(base_dir, 'fakeQRcode Detection', 'static'), os.path.join(frontend_dir, 'static', 'fake_qr'))
move_dir_contents(os.path.join(base_dir, 'EmailPhishing', 'static'), os.path.join(frontend_dir, 'static', 'email'))

# Move modules to backend
move_file(os.path.join(base_dir, 'url scam detection'), os.path.join(backend_dir, 'url_scam_detection'))
move_file(os.path.join(base_dir, 'fakeQRcode Detection'), os.path.join(backend_dir, 'fakeQRcode_Detection'))
move_file(os.path.join(base_dir, 'Malware Detection'), os.path.join(backend_dir, 'Malware_Detection'))
move_file(os.path.join(base_dir, 'EmailPhishing'), os.path.join(backend_dir, 'EmailPhishing'))

print("Done")
