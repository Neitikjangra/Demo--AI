# feature_extractor.py
import re
import socket
import ssl
import requests
from bs4 import BeautifulSoup
import tldextract
import whois
from rapidfuzz import fuzz
import imagehash
from PIL import Image
import io
import logging

logging.basicConfig(level=logging.INFO)
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) PhishDetectDemo/1.0"

# ---------- Lexical features ----------
def lexical_features(domain, target_domains=None):
    if target_domains is None:
        target_domains = ["example.com"]
    extracted = tldextract.extract(domain)
    domain_only = ".".join(p for p in [extracted.domain, extracted.suffix] if p)
    length = len(domain)
    special_chars = len(re.findall(r'[^a-zA-Z0-9.-]', domain))
    digits = len(re.findall(r'\d', domain))
    # simple entropy
    def entropy(s):
        import math, collections
        if not s:
            return 0
        freq = collections.Counter(s)
        probs = [v/len(s) for v in freq.values()]
        return -sum(p*math.log2(p) for p in probs)
    ent = entropy(domain)
    best_edit = max(fuzz.ratio(domain, t) for t in target_domains)
    return {
        "domain": domain,
        "domain_only": domain_only,
        "length": length,
        "special_chars": special_chars,
        "digits": digits,
        "entropy": ent,
        "best_edit_distance_to_targets": best_edit
    }

# ---------- WHOIS features ----------
def whois_features(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        registrar = None
        country = None
        # whois library sometimes returns dict-like or object
        try:
            registrar = w.registrar
        except Exception:
            registrar = None
        try:
            country = w.country
        except Exception:
            country = None
        import datetime
        age_days = None
        if creation:
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, str):
                try:
                    #creation = datetime.datetime.fromisoformat(creation)
                    print(f"Date of creation of {domain} is {creation}")
                except Exception:
                    creation = None
        if creation:
            #age_days = (datetime.datetime.utcnow() - creation).days
            age_days = datetime.datetime.date - creation
            print(f"total time of creation {age_days}")
        return {"registrar": registrar, "country": country, "age_days": age_days}
    except Exception as e:
        return {"registrar": None, "country": None, "age_days": None, "error": str(e)}

# ---------- SSL features ----------
def ssl_features(hostname, port=443, timeout=5):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get('issuer')
                subject = cert.get('subject')
                notBefore = cert.get('notBefore')
                notAfter = cert.get('notAfter')
                return {"issuer": issuer, "subject": subject, "notBefore": notBefore, "notAfter": notAfter}
    except Exception as e:
        return {"issuer": None, "subject": None, "error": str(e)}

# ---------- Content features ----------
def fetch_page(url, timeout=8):
    headers = {"User-Agent": USER_AGENT}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text

def content_features(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(separator=" ", strip=True)
    keywords = ["login", "otp", "password", "reset", "bank", "account", "verify", "signin"]
    found = {k: (k in text.lower()) for k in keywords}
    forms = soup.find_all("form")
    has_form = len(forms) > 0
    js = " ".join([s.get_text() for s in soup.find_all("script") if s.get_text()])
    obf_pattern = bool(re.search(r'\beval\(|atob\(|unescape\(|document\.write\(', js))
    return {"text_snippet": text[:2000], "keywords_found": found, "has_form": has_form, "js_obfuscated": obf_pattern}

# ---------- Visual features: phash ----------
def image_phash_from_bytes(img_bytes):
    img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    return str(imagehash.phash(img))

def compute_page_screenshot_phash_from_image(image_path_or_bytes):
    if isinstance(image_path_or_bytes, (bytes, bytearray)):
        return image_phash_from_bytes(image_path_or_bytes)
    else:
        img = Image.open(image_path_or_bytes)
        return str(imagehash.phash(img))


if __name__ == "__main__":  
    # Example usage 
    # compute_page_screenshot_phash_from_image("example.png")
    # fetch_page("https://www.sih.gov.in/")
    whois_features("https://www.sih.gov.in/")