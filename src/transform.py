import re
import sys
from urllib.parse import urlparse
from googlesearch import search
from tld import get_tld
import os.path
from src.exception import customException 

#Use of IP or not in domain
class transformationFunctions():

    def __init__(self):
        pass

    def has_ip_address(self, url):
        try:
            match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url) # IPv6
            if match:
                return 1
            else:             
               return 0
            
        except Exception as e:
            raise customException(e,sys)
        

    def count_dot(self, url):
        try:
            
            return url.count('.')

        except Exception as e:
            raise customException(e,sys)
        

    def count_www(self, url):
        try:
        
            return url.count('www')
        except Exception as e:
            raise customException(e,sys)
        
    
    def count_at(self, url):
        try:
            return url.count('@')
        except Exception as e:
            raise customException(e,sys)
        

    def count_directory(self, url):
        try:
            urldir = urlparse(url).path
        #     print(urldir)
            return urldir.count('/')
        except Exception as e:
            raise customException(e,sys)
        

    def count_embedded_domain(self, url):
        try:
            urldir = urlparse(url).path
            return urldir.count('//')
        except Exception as e:
            raise customException(e,sys)
        
    
    def suspicious_words(self, url):
        try:
            suspicious_terms = ['login', 'signin', 'secure', 'account', 'update', 'free', 'verify', 'ebayisapi', 'bank', 'ebay', 'paypal', 'click', 'confirm', 'webscr',]
            url_lower = url.lower()
            for term in suspicious_terms:
                if term in url_lower:
                    return 1
            return 0
        except Exception as e:
            raise customException(e,sys)
        
    
    def shortening_url(self,url):
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
    
    def count_https(self, url):
        try:
            return url.count('https')
        except Exception as e:
            raise customException(e,sys)
        

    def count_http(self, url):
        try:
            return url.count('http')
        except Exception as e:
            raise customException(e,sys)
        

    def count_percent(self, url):
        try:
            return url.count('%')
        except Exception as e:
            raise customException(e,sys)
        
    
    def count_question(self, url):
        try:
            return url.count('?')
        except Exception as e:
            raise customException(e,sys)
        

    def count_dash(self, url):
        try:
            return url.count('-')
        except Exception as e:
            raise customException(e,sys)
        

    def count_equal(self, url):
        try:
            return url.count('=')
        except Exception as e:
            raise customException(e,sys)
        

    def url_length(self, url):
        try:
            return len(str(url))
        except Exception as e:
            raise customException(e,sys)
        

    def hostname_length(self, url):
        try:
            hostname = urlparse(url).netloc
            return len(hostname)
        except Exception as e:
            raise customException(e,sys)
        

    #First Directory Length
    def first_directory_length(self, url):
        try:
            urlpath= urlparse(url).path
            try:
                return len(urlpath.split('/')[1])
            except:
                return 0
        except Exception as e:
            raise customException(e,sys)
        
    
    def top_level_domain_length(self, url):
        try:
            try:
                return len(get_tld(url))
            except:
                return -1
        except Exception as e:
            raise customException(e,sys)
        
    
    def count_digits(self, url):
        try:
            digits = 0
            for i in url:
                if i.isnumeric():
                    digits += 1
            return digits
        except Exception as e:
            raise customException(e,sys)
        

    def count_letters(self, url):
        try:
            letters = 0
            for i in url:
                if i.isalpha():
                    letters += 1
            return letters
        except Exception as e:
            raise customException(e,sys)
        
    def abnormal_url(self, url):
        try:
            hostname = urlparse(url).hostname
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:      
                return 1
            else:
                return 0

        except Exception as e:
            raise customException(e,sys)


