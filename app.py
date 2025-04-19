import joblib
import pandas as pd
import socket
import tldextract
from flask import Flask, request, render_template

app = Flask(__name__)
model = joblib.load('best_rfc_model.pkl')

# Get feature names from the model
feature_names = list(model.feature_names_in_) if hasattr(model, 'feature_names_in_') else [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
    'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde',
    'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn',
    'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path',
    'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
    'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
    'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension',
    'nb_redirection', 'nb_external_redirection', 'length_words_raw', 'char_repeat',
    'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
    'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host',
    'avg_word_path', 'phish_hints', 'domain_in_brand', 'brand_in_subdomain',
    'brand_in_path', 'suspecious_tld', 'statistical_report'
]

def extract_features(url):
    extracted = tldextract.extract(url)
    features = {}
    
    # Basic URL features
    features['length_url'] = len(url)
    features['length_hostname'] = len(extracted.domain)
    
    # IP check
    try:
        socket.inet_aton(extracted.domain)
        features['ip'] = 1
    except:
        features['ip'] = 0
    
    # Character counts - focus on most discriminative features
    features.update({
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_slash': url.count('/'),
        'nb_www': url.count('www'),
        'nb_com': url.count('.com'),
        'https_token': int(url.startswith('https://')),
        'http_in_path': int('http:' in url)
    })
    
    # Digit ratios
    digits_url = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = digits_url / len(url) if url else 0
    digits_host = sum(c.isdigit() for c in extracted.domain)
    features['ratio_digits_host'] = digits_host / len(extracted.domain) if extracted.domain else 0
    
    # Security features
    features.update({
        'punycode': int(any(ord(c) > 127 for c in url)),
        'port': 443 if url.startswith('https://') else 80
    })
    
    # Domain structure features - adjusted for better discrimination
    tld = extracted.suffix
    subdomain = extracted.subdomain
    features.update({
        'abnormal_subdomain': int(len(subdomain) > 0 and not subdomain.startswith('www')),
        'nb_subdomains': len(subdomain.split('.')),
        'random_domain': int(len(extracted.domain) < 6),  # Adjusted threshold
        'shortening_service': int(any(s in url.lower() for s in ['bit.ly', 'goo.gl', 'tinyurl.com'])),
        'tld_in_path': int(tld in url.split('/')[2]) if len(url.split('/')) > 2 else 0,
        'tld_in_subdomain': int(tld in subdomain)
    })
    
    # Set remaining features to 0
    for feature in feature_names:
        if feature not in features:
            features[feature] = 0
    
    return [features[feature] for feature in feature_names]

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url = ""
    
    if request.method == 'POST':
        url = request.form['url']
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            features = extract_features(url)
            features_df = pd.DataFrame([features], columns=feature_names)
            
            # Get prediction probabilities
            proba = model.predict_proba(features_df)[0]
            
            # Dynamic threshold based on feature analysis
            if (features_df['shortening_service'][0] == 1 or 
                features_df['ip'][0] == 1 or
                features_df['punycode'][0] == 1 or
                features_df['random_domain'][0] == 1):
                threshold = 0.55  # Lower threshold for suspicious features
            else:
                threshold = 0.85  # Higher threshold for normal URLs
                
            prediction = 1 if proba[1] >= threshold else 0
            result = "Phishing" if prediction == 1 else "Legitimate"
            
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render_template('index.html', result=result, url=url)

if __name__ == '__main__':
    app.run(debug=True)