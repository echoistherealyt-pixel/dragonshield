from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import re
import json
import os
from datetime import datetime

app = Flask(__name__)

with open('model/phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

HISTORY_FILE = 'model/history.json'

TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'instagram.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'wikipedia.org', 'github.com', 'linkedin.com', 'yahoo.com',
    'netflix.com', 'whatsapp.com', 'tiktok.com', 'reddit.com',
    'stackoverflow.com', 'gmail.com', 'outlook.com', 'bing.com'
]

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    history = history[:50]
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, ensure_ascii=False)

def get_hostname(url):
    try:
        hostname = url.split('/')[2] if len(url.split('/')) > 2 else url
        hostname = hostname.split(':')[0]
        return hostname
    except:
        return url

def is_trusted(url):
    hostname = get_hostname(url).replace('www.', '')
    for domain in TRUSTED_DOMAINS:
        if hostname == domain or hostname.endswith('.' + domain):
            return True
    return False

def extract_features_from_url(url):
    hostname = get_hostname(url)
    path = '/'.join(url.split('/')[3:]) if len(url.split('/')) > 3 else ''

    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': url.count('|'),
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': url.count('*'),
        'nb_colon': url.count(':'),
        'nb_comma': url.count(','),
        'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'),
        'nb_space': url.count(' '),
        'nb_www': 1 if 'www' in url else 0,
        'nb_com': 1 if '.com' in url else 0,
        'nb_dslash': url.count('//'),
        'http_in_path': 1 if 'http' in path else 0,
        'https_token': 1 if url.startswith('https') else 0,
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if len(hostname) > 0 else 0,
        'punycode': 1 if 'xn--' in url else 0,
        'port': 1 if re.search(r':\d{2,5}', hostname) else 0,
        'tld_in_path': 1 if re.search(r'\.(com|org|net|gov)', path) else 0,
        'tld_in_subdomain': 0,
        'abnormal_subdomain': 0,
        'nb_subdomains': len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0,
        'prefix_suffix': 1 if '-' in hostname else 0,
        'random_domain': 0,
        'shortening_service': 1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else 0,
        'path_extension': 1 if re.search(r'\.(exe|php|html|asp)', path) else 0,
        'nb_redirection': url.count('//') - 1 if url.count('//') > 1 else 0,
        'nb_external_redirection': 0,
        'length_words_raw': len(re.split(r'\W+', url)),
        'char_repeat': max([url.count(c) for c in set(url)]) if url else 0,
        'shortest_words_raw': min([len(w) for w in re.split(r'\W+', url) if w]) if url else 0,
        'shortest_word_host': min([len(w) for w in re.split(r'\W+', hostname) if w]) if hostname else 0,
        'shortest_word_path': min([len(w) for w in re.split(r'\W+', path) if w]) if path else 0,
        'longest_words_raw': max([len(w) for w in re.split(r'\W+', url) if w]) if url else 0,
        'longest_word_host': max([len(w) for w in re.split(r'\W+', hostname) if w]) if hostname else 0,
        'longest_word_path': max([len(w) for w in re.split(r'\W+', path) if w]) if path else 0,
        'avg_words_raw': sum([len(w) for w in re.split(r'\W+', url) if w]) / len(re.split(r'\W+', url)) if url else 0,
        'avg_word_host': sum([len(w) for w in re.split(r'\W+', hostname) if w]) / len(hostname.split('.')) if hostname else 0,
        'avg_word_path': sum([len(w) for w in re.split(r'\W+', path) if w]) / len(re.split(r'\W+', path)) if path else 0,
        'phish_hints': sum(w in url.lower() for w in ['login', 'verify', 'secure', 'account', 'update', 'banking', 'confirm', 'password']),
        'domain_in_brand': 0, 'brand_in_subdomain': 0, 'brand_in_path': 0,
        'suspecious_tld': 1 if any(t in hostname for t in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0,
        'statistical_report': 0, 'nb_hyperlinks': 0, 'ratio_intHyperlinks': 0,
        'ratio_extHyperlinks': 0, 'ratio_nullHyperlinks': 0, 'nb_extCSS': 0,
        'ratio_intRedirection': 0, 'ratio_extRedirection': 0, 'ratio_intErrors': 0,
        'ratio_extErrors': 0,
        'login_form': 1 if 'login' in url.lower() else 0,
        'external_favicon': 0, 'links_in_tags': 0, 'submit_email': 0,
        'ratio_intMedia': 0, 'ratio_extMedia': 0, 'sfh': 0, 'iframe': 0,
        'popup_window': 0, 'safe_anchor': 0, 'onmouseover': 0, 'right_clic': 0,
        'empty_title': 0, 'domain_in_title': 1, 'domain_with_copyright': 0,
        'whois_registered_domain': 1, 'domain_registration_length': 365,
        'domain_age': 365, 'web_traffic': 1, 'dns_record': 1,
        'google_index': 1, 'page_rank': 5
    }
    return list(features.values())

def get_risk_reasons(url):
    reasons = []
    hostname = get_hostname(url)
    if not url.startswith('https'):
        reasons.append('❌ الرابط مش بيستخدم HTTPS')
    if url.count('-') > 3:
        reasons.append('⚠️ عدد كبير من الشرطات في الرابط')
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        reasons.append('❌ الرابط بيستخدم IP مباشر بدل اسم الدومين')
    if any(w in url.lower() for w in ['login', 'verify', 'secure', 'banking', 'confirm', 'password']):
        reasons.append('⚠️ الرابط فيه كلمات مشبوهة')
    if any(t in hostname for t in ['.tk', '.ml', '.ga', '.cf', '.gq']):
        reasons.append('❌ امتداد الدومين مشبوه')
    if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl']):
        reasons.append('⚠️ الرابط مختصر وده ممكن يخبي وجهته الحقيقية')
    if len(url) > 75:
        reasons.append('⚠️ الرابط طويل جداً بشكل مريب')
    if url.count('.') > 4:
        reasons.append('⚠️ عدد كبير من النقاط في الرابط')
    return reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'مفيش رابط!'})

    if not url.startswith('http'):
        url = 'https://' + url

    trusted = is_trusted(url)
    if trusted:
        result = {
            'url': url,
            'result': 'legitimate',
            'confidence': 99.0,
            'is_phishing': False,
            'reasons': ['✅ موقع موثوق ومعروف عالمياً'],
            'time': datetime.now().strftime('%H:%M - %d/%m/%Y')
        }
    else:
        features = np.array([extract_features_from_url(url)])
        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        confidence = round(max(probability) * 100, 2)
        is_phishing = prediction == 'phishing'
        reasons = get_risk_reasons(url) if is_phishing else ['✅ لم يتم اكتشاف أنماط مشبوهة']
        result = {
            'url': url,
            'result': 'phishing' if is_phishing else 'legitimate',
            'confidence': confidence,
            'is_phishing': is_phishing,
            'reasons': reasons,
            'time': datetime.now().strftime('%H:%M - %d/%m/%Y')
        }

    save_history(result)
    return jsonify(result)

@app.route('/history')
def history():
    return jsonify(load_history())

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)