from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

# RECENT SCANS STORAGE

recent_scans = []

# TRUSTED DOMAINS

TRUSTED_DOMAINS = [
    "google.com",
    "amazon.com",
    "microsoft.com",
    "paypal.com",
    "facebook.com"
]

# LOOKALIKE / SPOOFED DOMAINS

LOOKALIKE_PATTERNS = {
    'google': ['g00gle', 'goog1e'],
    'amazon': ['amaz0n', 'arnazon'],
    'microsoft': ['micr0soft'],
    'paypal': ['paypa1'],
    'facebook': ['faceb00k']
}

# URL ANALYSIS

def analyze_url(url):

    reasons = []
    score = 0

    suggestion = None
    reputation = "Trusted"

    # FIX DOMAIN EXTRACTION

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # HTTPS CHECK

    if not url.startswith("https://"):

        reasons.append(
            "Website does not use HTTPS encryption"
        )

        score += 25

    # SUSPICIOUS KEYWORDS

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "bank",
        "update",
        "free",
        "account"
    ]

    for word in suspicious_keywords:

        if word in url.lower():

            reasons.append(
                f"Suspicious keyword detected: {word}"
            )

            score += 10

    # IP ADDRESS DETECTION

    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):

        reasons.append(
            "URL contains suspicious IP address"
        )

        score += 30

    # LOOKALIKE DOMAIN DETECTION

    for brand, fake_versions in LOOKALIKE_PATTERNS.items():

        for fake in fake_versions:

            if fake in domain:

                reasons.append(
                    f"Possible spoofed domain impersonating {brand}"
                )

                score += 30

                suggestion = f"{brand}.com"

    # DOMAIN REPUTATION

    if domain.count('-') >= 3:
        reputation = "Suspicious / Newly Generated"

    if len(domain) > 30:
        reputation = "Suspicious / Newly Generated"

    if re.search(r'\d', domain):
        reputation = "Suspicious / Newly Generated"

    # TRUSTED DOMAIN CHECK

    for trusted in TRUSTED_DOMAINS:

        if domain == trusted or domain.endswith("." + trusted):

            score -= 20

    # FINAL TRUST SCORE

    trust_score = max(0, min(100, 100 - score))

    # FINAL RESULT

    if score >= 60:
        result = "Phishing"

    elif score >= 30:
        result = "Suspicious"

    else:
        result = "Safe"

    return result, reasons, trust_score, suggestion, reputation

# HOME PAGE

@app.route('/')
def home():
    return render_template('index.html')

# TIPS PAGE

@app.route('/tips')
def tips():
    return render_template('tips.html')

# SCANNER PAGE

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():

    result = None
    reasons = []
    trust_score = None
    error = None

    suggestion = None
    reputation = None

    if request.method == 'POST':

        try:

            url = request.form['url'].strip()

            # VALIDATION

            if not url:

                error = "Please enter a URL."

            elif "." not in url:

                error = "Invalid URL format."

            elif len(url) > 300:

                error = "URL is too long."

            else:

                result, reasons, trust_score, suggestion, reputation = analyze_url(url)

                # SAVE RECENT SCANS

                recent_scans.insert(0, url)

                if len(recent_scans) > 5:
                    recent_scans.pop()

        except Exception:

            error = "Something went wrong during analysis."

    return render_template(
        'scanner.html',
        result=result,
        reasons=reasons,
        trust_score=trust_score,
        error=error,
        suggestion=suggestion,
        reputation=reputation,
        recent_scans=recent_scans
    )

# RUN APP

if __name__ == '__main__':
    app.run(debug=True)