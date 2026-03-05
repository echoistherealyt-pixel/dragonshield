from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import re
import json
import os
import requests
import unicodedata
from datetime import datetime

app = Flask(__name__)

with open('model/phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

HISTORY_FILE = 'model/history.json'
GOOGLE_API_KEY = 'AIzaSyAgYXIh_7MVZy6_t5NHsL65PmoeqKYVGYU'

DANGER_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
               '.club', '.work', '.click', '.link', '.live', '.online', '.pw',
               '.zip', '.mov', '.phishing', '.scam']

SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
              'short.link', 'tiny.cc', 'is.gd', 'rb.gy', 'cutt.ly',
              'buff.ly', 'adf.ly', 'bc.vc', 'clck.ru']

PHISH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification',
    'secure', 'security', 'account', 'update', 'confirm',
    'banking', 'password', 'passwd', 'credential',
    'suspend', 'suspended', 'unusual', 'alert', 'warning',
    'winner', 'prize', 'reward', 'urgent', 'limited',
    'expire', 'expired', 'cancel', 'invoice', 'payment',
    'support', 'helpdesk', 'authenticate', 'webscr',
    'cmd=_login', 'ebayisapi', 'signin', 'logon',
]

# قاعدة بيانات كاملة للمواقع المعروفة وأشكالها المزيفة
KNOWN_BRANDS = {
    'google':     ['g00gle', 'go0gle', 'googl3', 'g0ogle', 'googIe', 'gooogle', 'googgle', 'gogle'],
    'facebook':   ['faceb00k', 'facebok', 'faceboook', 'faceb0ok', 'faccbook', 'facbook', 'faecbook'],
    'paypal':     ['paypa1', 'paypall', 'paypa-l', 'paypai', 'paypa1', 'paypol', 'paypaI'],
    'amazon':     ['amaz0n', 'amazoon', 'arnazon', 'amazan', 'amzon', 'amazom', 'amazn'],
    'apple':      ['app1e', 'appl3', 'appie', 'aplle', 'aple', 'applee', 'appl-e'],
    'microsoft':  ['micros0ft', 'microsooft', 'micr0soft', 'microsofft', 'mlcrosoft'],
    'instagram':  ['1nstagram', 'instagrarr', 'inst4gram', 'instagrarn', 'instagran'],
    'twitter':    ['tw1tter', 'twiiter', 'tvvitter', 'twiter', 'twtter', 'twittter'],
    'netflix':    ['netf1ix', 'netfliix', 'netlfix', 'netflx', 'netflex', 'netfl1x'],
    'whatsapp':   ['whatsap', 'whatssapp', 'whats-app', 'whatapp', 'watsapp'],
    'youtube':    ['y0utube', 'youtub3', 'youutube', 'youtube-', 'you-tube'],
    'linkedin':   ['1inkedin', 'linkedln', 'linke-din', 'linked-in', 'linkediin'],
    'ebay':       ['3bay', 'eb4y', 'ebav', 'eba-y', 'ebaay'],
    'dropbox':    ['dr0pbox', 'dropb0x', 'drop-box', 'droopbox'],
    'gmail':      ['gmai1', 'gmaill', 'gmial', 'gmal', 'g-mail'],
    'outlook':    ['0utlook', 'outl00k', 'outlok', 'outIook', 'out1ook'],
}

# أرقام تتشابه مع حروف
DIGIT_TO_LETTER = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g'
}

# حروف تتشابه مع بعض
CONFUSABLE_CHARS = {
    'rn': 'm', 'vv': 'w', 'cl': 'd', 'I': 'l',
    'O': '0', 'l': '1',
}

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    history = history[:20]
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, ensure_ascii=False)

def get_hostname(url):
    try:
        hostname = url.split('/')[2] if len(url.split('/')) > 2 else url
        hostname = hostname.split(':')[0].replace('www.', '')
        return hostname.lower()
    except:
        return url.lower()

def normalize_domain(hostname):
    """بيحول الأرقام لحروف عشان يكشف التمويه"""
    normalized = hostname
    for digit, letter in DIGIT_TO_LETTER.items():
        normalized = normalized.replace(digit, letter)
    # شيل الـ unicode المشبوه وحوله لـ ASCII
    try:
        normalized = unicodedata.normalize('NFKD', normalized)
        normalized = normalized.encode('ascii', 'ignore').decode('ascii')
    except:
        pass
    return normalized

def check_google_safe_browsing(url):
    try:
        payload = {
            "client": {"clientId": "dragonshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}',
            json=payload, timeout=3
        )
        data = res.json()
        if data.get('matches'):
            threat_type = data['matches'][0]['threatType']
            threat_names = {
                'MALWARE': 'برمجيات خبيثة',
                'SOCIAL_ENGINEERING': 'تصيد احتيالي',
                'UNWANTED_SOFTWARE': 'برامج غير مرغوبة',
                'POTENTIALLY_HARMFUL_APPLICATION': 'تطبيق ضار'
            }
            threat_ar = threat_names.get(threat_type, threat_type)
            return True, f'❌ تحذير جوجل: الرابط يحتوي على {threat_ar}'
        return False, None
    except:
        return False, None

def analyze_url(url):
    hostname = get_hostname(url)
    normalized_hostname = normalize_domain(hostname)
    path = url.lower()
    risk_score = 0
    reasons = []

    # ===== 1. IP ADDRESS =====
    if re.search(r'(?<!\w)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\w)', hostname):
        risk_score += 45
        reasons.append('❌ الرابط بيستخدم IP مباشر بدل اسم الدومين')

    # ===== 2. NO HTTPS =====
    if not url.startswith('https'):
        risk_score += 20
        reasons.append('❌ الرابط مش بيستخدم HTTPS')

    # ===== 3. DANGEROUS TLD =====
    tld_match = [t for t in DANGER_TLDS if hostname.endswith(t)]
    if tld_match:
        risk_score += 35
        reasons.append(f'❌ امتداد الدومين خطير: {tld_match[0]}')

    # ===== 4. @ IN URL =====
    if '@' in url:
        risk_score += 40
        reasons.append('❌ الرابط فيه @ وده علامة خطر كبيرة')

    # ===== 5. DOUBLE SLASH IN PATH =====
    if url.count('//') > 1:
        risk_score += 25
        reasons.append('❌ الرابط فيه // متكررة')

    # ===== 6. URL SHORTENER =====
    if any(s in url for s in SHORTENERS):
        risk_score += 20
        reasons.append('⚠️ رابط مختصر — ممكن يخبي وجهته الحقيقية')

    # ===== 7. PUNYCODE / IDN ATTACK =====
    if 'xn--' in url:
        risk_score += 35
        reasons.append('❌ الرابط بيستخدم Punycode — هجوم homograph محتمل')

    # ===== 8. DIGIT SUBSTITUTION (g00gle, c0m, etc.) =====
    # كشف استبدال الأرقام بالحروف في اسم الدومين
    if normalized_hostname != hostname:
        domain_part = hostname.split('.')[0]
        normalized_domain_part = normalize_domain(domain_part)
        tld_part = '.'.join(hostname.split('.')[1:])
        normalized_tld = normalize_domain(tld_part)

        # تحقق إن الـ TLD نفسه متزيف (c0m بدل com)
        if normalized_tld != tld_part:
            risk_score += 50
            reasons.append(f'❌ امتداد الدومين مزيف: .{tld_part} بيتظاهر إنه .{normalized_tld}')

        # تحقق إن اسم الدومين بيتظاهر إنه موقع معروف
        for brand, fakes in KNOWN_BRANDS.items():
            if normalized_domain_part == brand or any(f in hostname for f in fakes):
                risk_score += 55
                reasons.append(f'❌ الرابط بيتظاهر إنه {brand} باستبدال حروف بأرقام مشابهة!')
                break

    # ===== 9. DIRECT HOMOGRAPH / TYPOSQUATTING =====
    for brand, fakes in KNOWN_BRANDS.items():
        if any(fake in hostname for fake in fakes):
            risk_score += 50
            reasons.append(f'❌ الرابط بيتظاهر إنه {brand} باستخدام كلمات مشابهة!')
            break

    # ===== 10. BRAND IN SUBDOMAIN (google.evil.com) =====
    parts = hostname.split('.')
    if len(parts) > 2:
        subdomain = '.'.join(parts[:-2])
        for brand in KNOWN_BRANDS.keys():
            if brand in subdomain:
                risk_score += 30
                reasons.append(f'⚠️ اسم {brand} موجود في الـ subdomain وده مشبوه')
                break

    # ===== 11. COMBOSQUATTING (google-secure.com, paypal-verify.com) =====
    for brand in KNOWN_BRANDS.keys():
        if brand in hostname:
            actual_domain = hostname.split('.')[0]
            if actual_domain != brand and '-' in actual_domain:
                risk_score += 35
                reasons.append(f'❌ الرابط بيستخدم {brand} مع إضافات مشبوهة')
                break

    # ===== 12. PHISHING KEYWORDS =====
    matched = [w for w in PHISH_KEYWORDS if w in path]
    if len(matched) >= 3:
        risk_score += 20
        reasons.append(f'⚠️ كلمات مشبوهة متعددة: {", ".join(matched[:3])}')
    elif len(matched) == 2:
        risk_score += 12
        reasons.append(f'⚠️ كلمات مشبوهة: {", ".join(matched[:2])}')
    elif len(matched) == 1:
        risk_score += 5

    # ===== 13. EXCESSIVE SUBDOMAINS =====
    subdomains = len(hostname.split('.')) - 2
    if subdomains > 3:
        risk_score += 20
        reasons.append(f'⚠️ عدد كبير جداً من الـ subdomains ({subdomains})')
    elif subdomains > 2:
        risk_score += 8

    # ===== 14. EXCESSIVE HYPHENS =====
    if hostname.count('-') > 3:
        risk_score += 15
        reasons.append('⚠️ عدد كبير من الشرطات في اسم الدومين')
    elif hostname.count('-') > 1:
        risk_score += 5

    # ===== 15. VERY LONG URL =====
    if len(url) > 120:
        risk_score += 15
        reasons.append(f'⚠️ الرابط طويل جداً ({len(url)} حرف)')
    elif len(url) > 75:
        risk_score += 5

    # ===== 16. RANDOM-LOOKING DOMAIN =====
    domain_name = hostname.split('.')[0]
    consonants = sum(1 for c in domain_name if c.isalpha() and c not in 'aeiou')
    if len(domain_name) > 8 and consonants / max(len(domain_name), 1) > 0.75:
        risk_score += 15
        reasons.append('⚠️ اسم الدومين يبدو عشوائي أو مولّد آلياً')

    # ===== 17. EXCESSIVE DIGITS IN DOMAIN =====
    digit_count = sum(c.isdigit() for c in domain_name)
    if digit_count >= 4:
        risk_score += 15
        reasons.append('⚠️ الدومين فيه أرقام كتير مشبوهة')
    elif digit_count >= 2:
        risk_score += 5

    # ===== 18. MULTIPLE DOTS =====
    if url.count('.') > 6:
        risk_score += 10
        reasons.append('⚠️ عدد كبير جداً من النقاط في الرابط')

    # ===== 19. SUSPICIOUS FILE EXTENSIONS =====
    if re.search(r'\.(exe|bat|cmd|scr|vbs|js|jar|zip|rar)($|\?)', url.lower()):
        risk_score += 30
        reasons.append('❌ الرابط بيحمّل ملف تنفيذي مشبوه')

    return min(risk_score, 100), reasons

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
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if url else 0,
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
        'punycode': 1 if 'xn--' in url else 0,
        'port': 1 if re.search(r':\d{2,5}', hostname) else 0,
        'tld_in_path': 1 if re.search(r'\.(com|org|net|gov)', path) else 0,
        'tld_in_subdomain': 0, 'abnormal_subdomain': 0,
        'nb_subdomains': len(hostname.split('.')) - 2 if len(hostname.split('.')) > 2 else 0,
        'prefix_suffix': 1 if '-' in hostname else 0,
        'random_domain': 0,
        'shortening_service': 1 if any(s in url for s in SHORTENERS) else 0,
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
        'phish_hints': sum(w in url.lower() for w in PHISH_KEYWORDS),
        'domain_in_brand': 0, 'brand_in_subdomain': 0, 'brand_in_path': 0,
        'suspecious_tld': 1 if any(t in hostname for t in DANGER_TLDS) else 0,
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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/protect')
def protect():
    return render_template('protect.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'مفيش رابط!'})
    if not url.startswith('http'):
        url = 'https://' + url

    # ===== STEP 1: Google Safe Browsing =====
    google_danger, google_reason = check_google_safe_browsing(url)
    if google_danger:
        result = {
            'url': url, 'result': 'phishing', 'confidence': 99,
            'is_phishing': True, 'risk_score': 95,
            'reasons': [google_reason, '⚠️ الرابط موجود في قاعدة بيانات جوجل للمواقع الخطيرة'],
            'time': datetime.now().strftime('%H:%M - %d/%m/%Y')
        }
        save_history(result)
        return jsonify(result)

    # ===== STEP 2: Rule-based analysis =====
    rule_score, reasons = analyze_url(url)

    # ===== STEP 3: ML Model =====
    features = np.array([extract_features_from_url(url)])
    prediction = model.predict(features)[0]
    ml_proba = model.predict_proba(features)[0]
    ml_confidence = max(ml_proba)
    ml_is_phishing = prediction == 'phishing'

    # ===== STEP 4: Smart Combined Decision =====
    if rule_score >= 50:
        is_phishing = True
        confidence = round(min(rule_score + 10, 99), 1)
    elif ml_is_phishing and ml_confidence > 0.85 and rule_score >= 15:
        is_phishing = True
        confidence = round((ml_confidence * 0.6 + rule_score / 100 * 0.4) * 100, 1)
    elif ml_is_phishing and rule_score < 15:
        is_phishing = False
        confidence = round(ml_confidence * 100, 1)
        reasons = ['✅ لم يتم اكتشاف أنماط مشبوهة واضحة']
    elif not ml_is_phishing and rule_score >= 35:
        is_phishing = True
        confidence = round(rule_score * 0.85, 1)
    else:
        is_phishing = False
        confidence = round(ml_confidence * 100, 1)
        reasons = ['✅ الرابط يبدو آمن — لم يتم اكتشاف تهديدات']

    result = {
        'url': url,
        'result': 'phishing' if is_phishing else 'legitimate',
        'confidence': confidence,
        'is_phishing': is_phishing,
        'risk_score': rule_score,
        'reasons': reasons if reasons else ['✅ الرابط يبدو آمن'],
        'time': datetime.now().strftime('%H:%M - %d/%m/%Y')
    }
    save_history(result)
    return jsonify(result)

@app.route('/history')
def history():
    return jsonify(load_history())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
