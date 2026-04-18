from pyexpat import features

from flask import Flask, request, jsonify
import joblib
import pandas as pd
from urllib.parse import urlparse
from googlesearch import search 

import re
import os
from urllib.parse import urlparse
from tld import get_tld

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def has_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' 
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0

def count_dot(url):
    return url.count('.')

def check_google_index(url):
    site = search(url, 5)
    if site:
        return 1
    else:
        return 0

def count_www(url):
    return url.count('www')

def count_at(url):
    return url.count('@')

def count_directory(url):
    return urlparse(url).path.count('/')

def count_embedded_domain(url):
    return urlparse(url).path.count('//')

def suspicious_words(url):
    suspicious_terms = ['login', 'signin', 'secure', 'account', 'update', 'free', 'verify', 
                        'ebayisapi', 'bank', 'ebay', 'paypal', 'click', 'confirm', 'webscr']
    url_lower = url.lower()
    for term in suspicious_terms:
        if term in url_lower:
            return 1
    return 0

def shortening_url(url):
    shorteners = [
        "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co",
        "tinyurl", "tr.im", "is.gd", "cli.gs", "yfrog.com", "migre.me",
        "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl",
        "snipurl.com", "short.to", "BudURL.com", "ping.fm", "post.ly",
        "Just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us",
        "doiop.com", "short.ie", "kl.am", "wp.me", "rubyurl.com",
        "om.ly", "to.ly", "bit.do", "lnkd.in", "db.tt", "qr.ae",
        "adf.ly", "bitly.com", "cur.lv", "tinyurl.com", "ity.im",
        "q.gs", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp",
        "buzurl.com", "cutt.us", "u.bb", "yourls.org", "prettylinkpro.com",
        "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com",
        "tweez.me", "v.gd", "link.zip.net"
    ]
    for service in shorteners:
        if service in url:
            return 1
    return 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_percent(url):
    return url.count('%')

def count_question(url):
    return url.count('?')

def count_dash(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(url)

def hostname_length(url):
    return len(urlparse(url).netloc)

def first_directory_length(url):
    path = urlparse(url).path
    try:
        return len(path.split('/')[1])
    except:
        return 0

def top_level_domain(url):
    try:
        return get_tld(url, as_object=True).tld
    except:
        return ''

def top_level_domain_length(tld):
    try:
        return len(tld)
    except:
        return -1

def count_digits(url):
    return sum(1 for c in url if c.isnumeric())

def count_letters(url):
    return sum(1 for c in url if c.isalpha())

def abnormal_url(url):
    hostname = str(urlparse(url).hostname)
    return 1 if re.search(hostname, url) else 0

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)

FEATURE_COLUMNS = [
    'url', 'has_ip', 'in_google_index', 'dot_count', 'www_count',
    'at_count', 'directory_count', 'embedded_domain_count', 
    'suspicious_word', 'shortening_url', 'https_count', 'http_count',
    'percent_count', 'question_count', 'dash_count', 'equal_count',
    'url_length', 'hostname_length', 'first_directory_length', 'tld',
    'tld_length', 'digit_count', 'letter_count', 'abnormal_url',
]


def preprocess_url(url: str) -> list:
    tld_value = top_level_domain(url)

    # Google index checks can fail/rate-limit; keep API stable

    features = {
        'has_ip': has_ip_address(url),
        'in_google_index': check_google_index(url),
        'dot_count': count_dot(url),
        'www_count': count_www(url),
        'at_count': count_at(url),
        'directory_count': count_directory(url),
        'embedded_domain_count': count_embedded_domain(url),
        'suspicious_word': suspicious_words(url),
        'shortening_url': shortening_url(url),
        'https_count': count_https(url),
        'http_count': count_http(url),
        'percent_count': count_percent(url),
        'question_count': count_question(url),
        'dash_count': count_dash(url),
        'equal_count': count_equal(url),
        'url_length': url_length(url),
        'hostname_length': hostname_length(url),
        'first_directory_length': first_directory_length(url),
        'tld_length': top_level_domain_length(tld_value),
        'digit_count': count_digits(url),
        'letter_count': count_letters(url),
        'abnormal_url': abnormal_url(url),
        
    }

    return features

@app.route('/')
def home():
    return "Hello, World!" 

@app.route('/check_link', methods=['POST'])
def check_link():
    print(request.json.get('url', ''))

    model = joblib.load('model/decision_tree_model.pkl')
    print(request.json.get('url', ''))
    url = request.json.get('url', '').strip()
    features = preprocess_url(url)
    #X = pd.DataFrame([features], columns=FEATURE_COLUMNS)
    prediction = model.predict(features)
    return jsonify({'malicious': bool(prediction[0])})

    
