# app.py
from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import os
from feature_extractor import lexical_features, whois_features, ssl_features, fetch_page, content_features
from text_model_demo import phishing_text_score
import tldextract

app = FastAPI(title="PhishDetect Demo API")

MODEL_PATH = "lexical_model.pkl"
if not os.path.exists(MODEL_PATH):
    raise RuntimeError("Model not found. Run 'python train_model.py' first.")

clf = joblib.load(MODEL_PATH)

class URLRequest(BaseModel):
    url: str
    target_domains: list = None

@app.post("/extract")
def extract(url_req: URLRequest):
    url = url_req.url
    target_domains = url_req.target_domains or ["example.com"]
    # parse domain/host
    ext = tldextract.extract(url)
    domain_host = ".".join(p for p in [ext.domain, ext.suffix] if p)
    lex = lexical_features(domain_host, target_domains=target_domains)
    who = whois_features(domain_host)
    ssl = ssl_features(domain_host)
    try:
        html = fetch_page(url)
        content = content_features(html)
        text_snip = content.get("text_snippet", "")
        phish_text_score = phishing_text_score(text_snip)
    except Exception as e:
        content = {"error": str(e)}
        phish_text_score = 0.0

    features = {
        "length": lex["length"],
        "special_chars": lex["special_chars"],
        "digits": lex["digits"],
        "entropy": lex["entropy"],
        "age_days": who.get("age_days") or 0,
        "has_form": int(content.get("has_form", False)),
        "js_obf": int(content.get("js_obfuscated", False))
    }

    return {
        "lexical": lex,
        "whois": who,
        "ssl": ssl,
        "content_preview": content,
        "text_phish_score": phish_text_score,
        "numeric_features_for_model": features
    }

@app.post("/predict")
def predict(url_req: URLRequest):
    ex = extract(url_req)
    feats = ex["numeric_features_for_model"]
    X = [[feats["length"], feats["special_chars"], feats["digits"], feats["entropy"], feats["age_days"], feats["has_form"], feats["js_obf"]]]
    prob = float(clf.predict_proba(X)[0][1])
    text_score = float(ex["text_phish_score"])
    final_score = prob * 0.6 + text_score * 0.4
    final_pct = round(final_score * 100, 2)
    category = "Benign"
    if final_pct >= 80:
        category = "Phishing"
    elif final_pct >= 40:
        category = "Suspected"
    return {
        "prob_phishing_model": prob,
        "text_phish_score": text_score,
        "final_risk_percent": final_pct,
        "category": category,
        "details": ex
    }

# run: uvicorn app:app --reload
