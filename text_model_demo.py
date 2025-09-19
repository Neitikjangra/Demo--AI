"""
text_model_demo.py
------------------
Lightweight placeholder for phishing detection using HuggingFace transformers.

⚠️ This is for DEMO ONLY.
- It shows how you can plug in an NLP model (like BERT/DistilBERT).
- For production, you should fine-tune a phishing-specific dataset.

Dependencies:
    pip install transformers torch
"""

from transformers import pipeline

def init_text_model():
    """
    Initialize a HuggingFace text classification pipeline.
    For demo, we use sentiment-analysis model as placeholder.
    Replace with phishing-tuned model in production.
    """
    print("[INFO] Loading HuggingFace model... (this may take a minute)")
    model = pipeline("sentiment-analysis")  # placeholder
    return model

def predict_text_risk(model, text: str):
    """
    Run text through the placeholder model.
    In production: Replace with phishing-tuned classifier.
    """
    prediction = model(text)[0]
    label = prediction['label']
    score = prediction['score']

    # Map sentiment labels to phishing risk (DEMO ONLY)
    if label == "NEGATIVE":
        risk_label = "Suspicious / Possible Phishing"
    else:
        risk_label = "Likely Safe"

    return {
        "input_text": text,
        "sentiment_label": label,
        "confidence": round(score, 4),
        "risk_assessment": risk_label
    }

if __name__ == "__main__":
    # Demo example
    model = init_text_model()

    examples = [
        "Your account has been suspended, click here to verify your password.",
        "Welcome back! Enjoy your shopping experience with us.",
        "Urgent! Update your payment information to avoid account closure."
    ]

    for text in examples:
        result = predict_text_risk(model, text)
        print("\n--- Analysis ---")
        for k, v in result.items():
            print(f"{k}: {v}")
