# feature_extraction.py

import re
import socket
import ssl
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

def extract_features(url):

    features = {}

    parsed = urlparse(url)
    domain = parsed.netloc

    # -------------------------------------------------
    # 1. having_IP_Address
    # -------------------------------------------------
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    features['having_IP_Address'] = 1 if re.match(ip_pattern, domain) else -1

    # -------------------------------------------------
    # 2. URL_Length
    # -------------------------------------------------
    url_length = len(url)

    if url_length < 54:
        features['URL_Length'] = -1
    elif 54 <= url_length <= 75:
        features['URL_Length'] = 0
    else:
        features['URL_Length'] = 1

    # -------------------------------------------------
    # 3. Shortining_Service
    # -------------------------------------------------
    shortening_services = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd"

    features['Shortining_Service'] = 1 if re.search(shortening_services, url) else -1

    # -------------------------------------------------
    # 4. having_At_Symbol
    # -------------------------------------------------
    features['having_At_Symbol'] = 1 if '@' in url else -1

    # -------------------------------------------------
    # 5. double_slash_redirecting
    # -------------------------------------------------
    features['double_slash_redirecting'] = 1 if url.rfind('//') > 6 else -1

    # -------------------------------------------------
    # 6. Prefix_Suffix
    # -------------------------------------------------
    features['Prefix_Suffix'] = 1 if '-' in domain else -1

    # -------------------------------------------------
    # 7. having_Sub_Domain
    # -------------------------------------------------
    dots = domain.count('.')

    if dots == 1:
        features['having_Sub_Domain'] = -1
    elif dots == 2:
        features['having_Sub_Domain'] = 0
    else:
        features['having_Sub_Domain'] = 1

    # -------------------------------------------------
    # 8. SSLfinal_State
    # -------------------------------------------------
    features['SSLfinal_State'] = 1 if parsed.scheme == 'https' else -1

    # -------------------------------------------------
    # 9. Domain_registeration_length
    # -------------------------------------------------
    try:
        domain_info = whois.whois(domain)

        expiration_date = domain_info.expiration_date

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        registration_length = abs((expiration_date - datetime.now()).days)

        features['Domain_registeration_length'] = 1 if registration_length >= 365 else -1

    except:
        features['Domain_registeration_length'] = -1

    # -------------------------------------------------
    # Request webpage
    # -------------------------------------------------
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
    except:
        soup = None

    # -------------------------------------------------
    # 10. Favicon
    # -------------------------------------------------
    try:
        favicon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        features['Favicon'] = -1 if favicon else 1
    except:
        features['Favicon'] = 0

    # -------------------------------------------------
    # 11. port
    # -------------------------------------------------
    try:
        port = parsed.port

        if port:
            features['port'] = 1
        else:
            features['port'] = -1

    except:
        features['port'] = -1

    # -------------------------------------------------
    # 12. HTTPS_token
    # -------------------------------------------------
    features['HTTPS_token'] = 1 if 'https' in domain else -1

    # -------------------------------------------------
    # 13. Request_URL
    # -------------------------------------------------
    try:
        imgs = soup.find_all('img')

        external = 0

        for img in imgs:
            src = img.get('src')

            if src and domain not in src:
                external += 1

        percentage = external / len(imgs) if len(imgs) > 0 else 0

        if percentage < 0.22:
            features['Request_URL'] = -1
        elif percentage <= 0.61:
            features['Request_URL'] = 0
        else:
            features['Request_URL'] = 1

    except:
        features['Request_URL'] = 0

    # -------------------------------------------------
    # 14. URL_of_Anchor
    # -------------------------------------------------
    try:
        anchors = soup.find_all('a')

        unsafe = 0

        for a in anchors:
            href = a.get('href')

            if href:
                if "#" in href or "javascript" in href.lower():
                    unsafe += 1

        percentage = unsafe / len(anchors) if len(anchors) > 0 else 0

        if percentage < 0.31:
            features['URL_of_Anchor'] = -1
        elif percentage <= 0.67:
            features['URL_of_Anchor'] = 0
        else:
            features['URL_of_Anchor'] = 1

    except:
        features['URL_of_Anchor'] = 0

    # -------------------------------------------------
    # 15. Links_in_tags
    # -------------------------------------------------
    try:
        links = soup.find_all(['link', 'script'])

        external = 0

        for tag in links:

            src = tag.get('href') or tag.get('src')

            if src and domain not in src:
                external += 1

        percentage = external / len(links) if len(links) > 0 else 0

        if percentage < 0.17:
            features['Links_in_tags'] = -1
        elif percentage <= 0.81:
            features['Links_in_tags'] = 0
        else:
            features['Links_in_tags'] = 1

    except:
        features['Links_in_tags'] = 0

    # -------------------------------------------------
    # 16. SFH
    # -------------------------------------------------
    try:
        forms = soup.find_all('form')

        if len(forms) == 0:
            features['SFH'] = -1
        else:
            action = forms[0].get('action')

            if action == "" or action == "about:blank":
                features['SFH'] = 1
            else:
                features['SFH'] = -1

    except:
        features['SFH'] = 0

    # -------------------------------------------------
    # 17. Submitting_to_email
    # -------------------------------------------------
    try:
        forms = soup.find_all('form')

        found = False

        for form in forms:
            action = form.get('action')

            if action and 'mailto:' in action:
                found = True

        features['Submitting_to_email'] = 1 if found else -1

    except:
        features['Submitting_to_email'] = 0

    # -------------------------------------------------
    # 18. Abnormal_URL
    # -------------------------------------------------
    try:
        hostname = socket.gethostbyname(domain)

        features['Abnormal_URL'] = -1 if hostname else 1

    except:
        features['Abnormal_URL'] = 1

    # -------------------------------------------------
    # 19. Redirect
    # -------------------------------------------------
    try:
        features['Redirect'] = 1 if len(response.history) > 2 else -1
    except:
        features['Redirect'] = 0

    # -------------------------------------------------
    # 20. on_mouseover
    # -------------------------------------------------
    try:
        features['on_mouseover'] = 1 if "onmouseover" in response.text else -1
    except:
        features['on_mouseover'] = 0

    # -------------------------------------------------
    # 21. RightClick
    # -------------------------------------------------
    try:
        features['RightClick'] = 1 if "event.button==2" in response.text else -1
    except:
        features['RightClick'] = 0

    # -------------------------------------------------
    # 22. popUpWidnow
    # -------------------------------------------------
    try:
        features['popUpWidnow'] = 1 if "alert(" in response.text else -1
    except:
        features['popUpWidnow'] = 0

    # -------------------------------------------------
    # 23. Iframe
    # -------------------------------------------------
    try:
        features['Iframe'] = 1 if soup.find_all('iframe') else -1
    except:
        features['Iframe'] = 0

    # -------------------------------------------------
    # 24. age_of_domain
    # -------------------------------------------------
    try:
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = (datetime.now() - creation_date).days

        features['age_of_domain'] = 1 if age >= 180 else -1

    except:
        features['age_of_domain'] = 0

    # -------------------------------------------------
    # 25. DNSRecord
    # -------------------------------------------------
    try:
        socket.gethostbyname(domain)
        features['DNSRecord'] = -1
    except:
        features['DNSRecord'] = 1

    # -------------------------------------------------
    # 26. web_traffic
    # -------------------------------------------------
    features['web_traffic'] = 0

    # -------------------------------------------------
    # 27. Page_Rank
    # -------------------------------------------------
    features['Page_Rank'] = 0

    # -------------------------------------------------
    # 28. Google_Index
    # -------------------------------------------------
    features['Google_Index'] = 0

    # -------------------------------------------------
    # 29. Links_pointing_to_page
    # -------------------------------------------------
    try:
        links = soup.find_all('a')

        if len(links) == 0:
            features['Links_pointing_to_page'] = 1
        elif len(links) <= 2:
            features['Links_pointing_to_page'] = 0
        else:
            features['Links_pointing_to_page'] = -1

    except:
        features['Links_pointing_to_page'] = 0

    # -------------------------------------------------
    # 30. Statistical_report
    # -------------------------------------------------
    suspicious_ips = ['146.112.61.108']

    try:
        ip = socket.gethostbyname(domain)

        features['Statistical_report'] = 1 if ip in suspicious_ips else -1

    except:
        features['Statistical_report'] = 0

    return features