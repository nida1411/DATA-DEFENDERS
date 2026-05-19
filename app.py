from flask import Flask, render_template, request
from urllib.parse import urlparse
import re

app = Flask(__name__)

SUSPICIOUS_WORDS = [
    'login',
    'verify',
    'bank',
    'secure',
    'account',
    'update',
    'signin'
]

TRUSTED_DOMAINS = [
    'google.com',
    'github.com',
    'microsoft.com'
]
LOOKALIKE_PATTERNS = {
    'google': ['g00gle', 'goog1e'],
    'amazon': ['amaz0n', 'arnazon'],
    'microsoft': ['micr0soft'],
    'paypal': ['paypa1'],
    'facebook': ['faceb00k']
}


def analyze_url(url):

    score = 0
    reasons = []

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # HTTPS check
    if not url.startswith('https://'):
        reasons.append('Website does not use HTTPS')
        score += 15

    # @ symbol
    if '@' in url:
        reasons.append('Contains @ symbol')
        score += 20

    # Long URL
    if len(url) > 75:
        reasons.append('URL is unusually long')
        score += 15

    # Too many hyphens
    if url.count('-') >= 3:
        reasons.append('Too many hyphens detected')
        score += 10

    # Too many dots
    if url.count('.') >= 5:
        reasons.append('Too many dots detected')
        score += 10

    # IP Address detection
    if re.match(r'^(\\d{1,3}\\.){3}\\d{1,3}$', domain):
        reasons.append('Uses IP address instead of domain')
        score += 25

    # Suspicious keywords
    for word in SUSPICIOUS_WORDS:
        if word in url.lower():
            reasons.append(f'Suspicious keyword: {word}')
            score += 8
    # Lookalike domain detection

    for brand, fake_versions in LOOKALIKE_PATTERNS.items():

        for fake in fake_versions:

            if fake in domain:
                reasons.append(
                    f'Possible typosquatting attack detected impersonating {brand}'
                )

                score += 30        

    # Trusted domains
    trusted = False

    for safe in TRUSTED_DOMAINS:
        if safe in domain:
            trusted = True
            break

    if trusted:
        score -= 20

    trust_score = max(0, min(100, 100 - score))

    # Final result
    if trust_score >= 75:
        result = 'Safe'

    elif trust_score >= 45:
        result = 'Suspicious'

    else:
        result = 'Phishing'

    return result, reasons, trust_score


@app.route('/', methods=['GET', 'POST'])
def home():

    result = None
    reasons = []
    trust_score = None
    error = None

    if request.method == 'POST':

        try:

            url = request.form['url'].strip()

            # Validation
            if not url:
                error = "Please enter a URL."

            elif "." not in url:
                error = "Invalid URL format."

            elif len(url) > 300:
                error = "URL is too long."

            else:
                result, reasons, trust_score = analyze_url(url)

        except Exception:
            error = "Something went wrong during analysis."

    return render_template(
        'index.html',
        result=result,
        reasons=reasons,
        trust_score=trust_score,
        error=error
    )


@app.route('/tips')
def tips():
    return render_template('tips.html')

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():

    result = None
    reasons = []
    trust_score = None
    error = None

    if request.method == 'POST':

        try:

            url = request.form['url'].strip()

            if not url:
                error = "Please enter a URL."

            elif "." not in url:
                error = "Invalid URL format."

            elif len(url) > 300:
                error = "URL is too long."

            else:
                result, reasons, trust_score = analyze_url(url)

        except Exception:
            error = "Something went wrong during analysis."

    return render_template(
        'scanner.html',
        result=result,
        reasons=reasons,
        trust_score=trust_score,
        error=error
    )


if __name__ == '__main__':
    app.run(debug=True)