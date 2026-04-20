# %%
import numpy as np  
import matplotlib.pyplot as plt
import pandas as pd

import torch as th
from torch import nn
import seaborn as sns

# %%
df = pd.read_csv('malicious_phish.csv')
df.head()


# %%
df.describe()

# %%
df['type'].value_counts()

# %%
plt.figure(figsize=(10,5))
plt.title('Distribution of Malicious and Benign URLs')
sns.countplot(x='type',data = df)
plt.xlabel('URL Type')
plt.ylabel('Count')


# %% [markdown]
# **Feature Engineering**
#  
# We will now extract features from URLs, and use them to train machine learning model

# %% [markdown]
# has_ip_address: It's common for malicious links to have an ip address instead of domain name, this function if url has a IP address in domain.

# %%
import re  

def has_ip_address(url):
    # Regular expression to match IPv4 addresses
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url) # IPv6

    if match:
        return 1
    else:
        return 0
    
df['has_ip'] = df['url'].apply(has_ip_address)
df[df['has_ip'] == 1].head()
    

# %%
df['has_ip'].value_counts()

# %% [markdown]
# check_google_index: Will check if the URL is in google search console

# %% [markdown]
# count_dot: checks, if the url has multiple subdomains, by checking the ammount of dots, url's with three or more sub domains are more likely to be malicious 

# %%
def count_dot(url):
    return url.count('.')

df['dot_count'] = df['url'].apply(count_dot)

# %%
df['dot_count'].value_counts()

# %% [markdown]
# count_www: Counts the number of www in url, most safe sites will have only one instance of www.

# %%
def count_www(url):
    return url.count('www')

df['www_count']=df['url'].apply(count_www)

# %%
df['www_count'].value_counts()

# %% [markdown]
# count@: Counts the number of @ in url.

# %%
def count_at(url):
    return url.count('@')

df['at_count'] = df['url'].apply(count_at)

# %%
df['at_count'].value_counts()

# %% [markdown]
# count_directory: The more directories, the more likely a url is suspicious. 

# %%
from urllib.parse import urlparse

def count_directory(url):
    urldir=urlparse(url).path
    return urldir.count('/')

df['directory_count'] = df['url'].apply(count_directory)

# %%
df['directory_count'].value_counts()

# %% [markdown]
# count_embedded_domain: Multiple embededded domains generally indicates a link is suspicious 

# %%
def count_embedded_domain(url):
    urldir=urlparse(url).path
    return urldir.count('//')

df['embedded_domain_count'] = df['url'].apply(count_embedded_domain)

# %%
df['embedded_domain_count'].value_counts()

# %% [markdown]
# suspicious_words: Checks for suspicious words (login, Paypal, bank, etc) which indicate url may be malicious

# %%
def suspicious_words(url):
    suspicious_terms = ['login', 'signin', 'secure', 'account', 'update', 'free', 'verify', 'ebayisapi', 'bank', 'ebay', 'paypal', 'click', 'confirm', 'webscr',]
    url_lower = url.lower()
    for term in suspicious_terms:
        if term in url_lower:
            return 1
    return 0

df['suspicious_word'] = df['url'].apply(suspicious_words)

# %%
df['suspicious_word'].value_counts()

# %% [markdown]
# shortening_url: checks if url uses URL shortening services (bit. \ly , goo.gl)

# %%
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
    
df['shortening_url'] = df['url'].apply(shortening_url)

# %%
df['shortening_url'].value_counts()

# %% [markdown]
# count_https: Presence of https protocol generally indicates a website is safe.

# %%
def count_https(url):
    return url.count('https')

df['https_count'] = df['url'].apply(count_https)

# %%
df['https_count'].value_counts()

# %% [markdown]
# count_http: Presence of multiple http in url indicates it may be malicious.

# %%
def count_http(url):
    return url.count('http')

df['http_count'] = df['url'].apply(count_http)

# %%
df['http_count'].value_counts()

# %% [markdown]
# count_percent: Safe sites generally will contain less % symbols than malicious sites.

# %%
def count_percent(url):
    return url.count('%')

df['percent_count'] = df['url'].apply(count_percent)

# %%
df['percent_count'].value_counts()

# %% [markdown]
# count_question: ? are followed by query string that contains data to be passed to server, the more instances of it the more suspicious it's likely to be. 

# %%
def count_question(url):
    return url.count('?')   

df['question_count'] = df['url'].apply(count_question)

# %%
df['question_count'].value_counts()

# %% [markdown]
# count_dash: dashes are added to make malicious websites look legit.

# %%
def count_dash(url):
    return url.count('-')

df['dash_count'] = df['url'].apply(count_dash)

# %%
df['dash_count'].value_counts()

# %% [markdown]
# count_equal: Equal (=) signs indicate passing of variable values from one page to another, the more present the higher chance an url is suspicious.

# %%
def count_equal(url):
    return url.count('=')

df['equal_count'] = df['url'].apply(count_equal)

# %%
df['equal_count'].value_counts()    

# %% [markdown]
# url_length: Malicious links may contain longer urls to hide domain names

# %%
def url_length(url):
    return len(url)

df['url_length'] = df['url'].apply(url_length)

# %%
df['url_length'].value_counts()

# %% [markdown]
# hostname_length: A longer hostname is also suspicious 

# %%
def hostname_length(url):
    hostname = urlparse(url).netloc
    return len(hostname)

df['hostname_length'] = df['url'].apply(hostname_length)

# %%
df['hostname_length'].value_counts()

# %% [markdown]
# first_dir_length: The length of the first directory is also relevant when figuring out if a link is safe or suspicious 

# %%
from tld import get_tld


def first_directory_length(url):
    path = urlparse(url).path
    try:
        return len(path.split('/')[1])
    except:  
        return 0
    
df['first_directory_length'] = df['url'].apply(first_directory_length)

# %%
df['first_directory_length'].value_counts()

# %% [markdown]
# top_level_domain_length: Top level domain is the domain with the highest level in hierachy of DNS, ex: .com, .ca. Most safe urls top level domain length ranges from 2-3.

# %%
def top_level_domain(url):
    try:
        return get_tld(url, as_object=True).tld
    except:
        return ''

df['tld']=df['url'].apply(top_level_domain)

def top_level_domain_length(tld):
    try:
        return len(tld)
    except:
        return -1
    
df['tld_length'] = df['tld'].apply(top_level_domain_length)

# %%
df['tld'].value_counts()

# %%
df['tld_length'].value_counts()

# %% [markdown]
# count_digits: Safe urls generally won't have digits in them.

# %%
def count_digits(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits+=1
    return digits

df['digit_count'] = df['url'].apply(count_digits)

# %%
df['digit_count'].value_counts()

# %% [markdown]
# count_letters: The number of letter is also important as attackers many try to increase length of URL to hide URL. 

# %%
def count_letters(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters+=1
    return letters

df['letter_count'] = df['url'].apply(count_letters)

# %%
df['letter_count'].value_counts()

# %% [markdown]
# abnormal_url
# 
# 

# %%
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:      
        return 1
    else:
       
        return 0


df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))

# %%
df['abnormal_url'].value_counts()

# %%
df.head()

# %% [markdown]
# Label encoding

# %%
from sklearn.preprocessing import LabelEncoder

label_encoder = LabelEncoder()

df['type_code'] = label_encoder.fit_transform(df['type'])



# %%
df.columns

# %%
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))

X_text = vectorizer.fit_transform(df['url'])

X_manual = df[['has_ip', 'dot_count', 'www_count', 'at_count', 'directory_count', 'embedded_domain_count', 'suspicious_word', 
        'shortening_url', 'https_count', 'http_count', 'percent_count', 'question_count', 'dash_count', 'equal_count', 'url_length', 
        'hostname_length', 'first_directory_length', 'tld_length', 'digit_count', 'letter_count', 'abnormal_url'
        ]]

X = hstack([X_text, X_manual])
y = df['type_code']

# %% [markdown]
# Spliting the dataset

# %%
from sklearn.model_selection import train_test_split

X_train, X_test, Y_train,Y_test = train_test_split(X,y,test_size=0.2, random_state=42)

X_train


# %% [markdown]
# Creating the model. 

# %%
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

def result (y_pred,y_test):
    accuracy=accuracy_score(y_test, y_pred)*100

    precision,recall,f1_score,support = precision_recall_fscore_support(y_test, y_pred, average='weighted')

    result={
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score
    }

    print(classification_report(y_test, y_pred,target_names=['benign','defacement','phishing','malware']))

    return result

# %%
from sklearn.metrics import confusion_matrix

def create_confusion_matrix(y_test,y_pred):
    cm = confusion_matrix(y_test, y_pred)
    cm_df = pd.DataFrame(cm, index=['benign','defacement','phishing','malware'], columns=['benign','defacement','phishing','malware'])
    plt.figure(figsize=(8,6))
    sns.heatmap(cm_df, annot=True, fmt='.1f')
    plt.title('Confusion Matrix')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.show()

# %%
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, roc_curve
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
import matplotlib.pyplot as plt
import seaborn as sns
from termcolor import colored
import joblib

#Defining classifiers
models = {
    #"Logistic Regression": LogisticRegression(),
    #"Decision Tree": DecisionTreeClassifier(),
    "Random_Forest": RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_leaf=5,
    class_weight='balanced',
    random_state=42
),
    #"Gradient Boosting": GradientBoostingClassifier(),
    #"AdaBoost": AdaBoostClassifier(),
    #"XGBoost": XGBClassifier(),
    #"CatBoost": CatBoostClassifier(verbose=0)
}

for model_name,model in models.items():
    
    model.fit(X_train,Y_train)

    #Predctions on test and train data
    y_test_pred = model.predict(X_test)
    y_train_pred = model.predict(X_train)

    #Calculating metrics for train data
    train_accuracy = accuracy_score(Y_train, y_train_pred)
    train_precision = precision_score(Y_train, y_train_pred, average='weighted')
    train_recall = recall_score(Y_train, y_train_pred, average='weighted')
    train_f1 = f1_score(Y_train, y_train_pred, average='weighted')

    #Calculating metrics for test data
    accuracy = accuracy_score(Y_test, y_test_pred)
    precision = precision_score(Y_test, y_test_pred, average='weighted')
    recall = recall_score(Y_test, y_test_pred, average='weighted')
    f1 = f1_score(Y_test, y_test_pred, average='weighted')

    #Generating confusion matrix
    cm = confusion_matrix(Y_test, y_test_pred)
    plt.figure(figsize=(8,6))
    sns.heatmap(cm,annot=True, cmap='Blues', fmt='g')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title(f'{model_name} - Confusion Matrix')
    plt.show()

    #Printing train results
    print(colored(f'{model_name} - Train Metrics:', 'blue'))
    print(f'Train accuracy: {train_accuracy:.4f}')
    print(f'Train precision: {train_precision:.4f}')
    print(f'Train recall: {train_recall:.4f}')
    print(f'Train F1-score: {train_f1:.4f}')

    #Printing test results
    print(colored(f'{model_name} - Test Metrics:', 'green'))
    print(f'Test accuracy: {accuracy:.4f}')
    print(f'Test precision: {precision:.4f}')
    print(f'Test recall: {recall:.4f}')
    print(f'Test F1-score: {f1:.4f}')

    joblib.dump(model, f'{model_name}_model.pkl')

joblib.dump(vectorizer, 'tfidf_vectorizer.pkl')
    

# %% [markdown]
# Hyperparameter tuning

# %%
#Logistic Regression 
# logistic_regression_parameters = [
#     {
#         "solver": ["lbfgs", "newton-cg", "sag"],
#         "penalty": ["l2", None],
#         "C": [0.01, 0.1, 1, 10, 100],
#         "max_iter": [1000],
#     },
#     {
#         "solver": ["liblinear"],
#         "penalty": ["l1", "l2"],
#         "C": [0.01, 0.1, 1, 10, 100],
#         "max_iter": [1000],
#     },
#     {
#         "solver": ["saga"],
#         "penalty": ["l1", "l2", "elasticnet", None],
#         "l1_ratio": [0.5],
#         "C": [0.01, 0.1, 1, 10, 100],
#         "max_iter": [1000],
#     },
# ]

#Decision Tree
# decision_tree_parameters = {
#     'criterion': ['gini', 'entropy'],
#     'max_depth': [None, 5, 10, 15],
#     'min_samples_split': [2, 5, 10],
#     'min_samples_leaf': [1, 2, 4],
#     'max_features': [None, 'sqrt', 'log2']
# }

# #Random Forest
random_forest_parameters = {
    'n_estimators': [100,300],
    'max_depth': [None, 10],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4],
    'max_features': [None, 'sqrt', 'log2']
}

# #Gradient Boosting
# gradient_boosting_parameters = {
#     'n_estimators': [100, 200 ,500],
#     'learning_rate': [0.01, 0.1, 0.2],
#     'max_depth': [3, 5, 10],
#     'min_samples_split': [2, 5, 10],
#     'min_samples_leaf': [1, 2, 4],
#     'max_features': [None, 'sqrt', 'log2']
# }

# #XGBoost
# xgb_parameters = {
#     'n_estimators': [100, 200, 500],
#     'learning_rate': [0.01, 0.1, 0.2],
#     'max_depth': [3, 5, 10],
#     'min_child_weight': [1, 3, 5],
#     'subsample': [0.5,0.8, 1.0],
#     'colsample_bytree': [0.5, 0.8, 1.0]
# }

# #CatBoost
# catboost_parameters = {
#     'learning_rate': [0.01, 0.1, 1],
#     'n_estimators': [100, 200, 500],
#     'depth': [3, 5, 10],
#     'min_data_in_leaf': [1, 3, 5],
#     'l2_leaf_reg': [1, 3, 5],
# }

# #AdaBoost
# adaboost_parameters = {
#     'n_estimators': [50, 100, 200],
#     'learning_rate': [0.01, 0.1, 1],
#     'algorithm': ['SAMME', 'SAMME.R']
# }

#Setting up hyperparameter tuning for each model

parameters = {
    #'Logistic Regression': logistic_regression_parameters, 
    #'Decision Tree': decision_tree_parameters,
    # 'Random Forest': random_forest_parameters,
    # 'Gradient Boosting': gradient_boosting_parameters,
    # 'XGBoost': xgb_parameters,
    # 'CatBoost': catboost_parameters,
    # 'AdaBoost': adaboost_parameters
}


# %%
# from sklearn.tree import DecisionTreeClassifier
# from sklearn.model_selection import GridSearchCV, StratifiedKFold
# from sklearn.metrics import accuracy_score, make_scorer

# # Cross-validation setup
# cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
# scoring_metric = make_scorer(accuracy_score)

# # Decision Tree parameters and model
# # decision_tree_parameters = {
# #     'criterion': ['gini', 'entropy'],
# #     'max_depth': [None, 5, 10, 15],
# #     'min_samples_split': [2, 5, 10],
# #     'min_samples_leaf': [1, 2, 4],
# #     'max_features': [None, 'sqrt', 'log2']
# # }

# # dt_model = DecisionTreeClassifier(random_state=42)

# rf_model = RandomForestClassifier(
#     n_estimators=200,
#     max_depth=10,
#     min_samples_leaf=5,
#     class_weight='balanced',
#     random_state=42
# )

# # Grid search — only 216 combos, fast enough to use GridSearchCV directly
# print(colored('Tuning hyperparameters for Decision Tree...', 'red', attrs=['bold']))
# clf = GridSearchCV(dt_model, decision_tree_parameters, scoring=scoring_metric, cv=cv, n_jobs=-1)
# clf.fit(X_train, Y_train)

# print(f"Best hyperparameters: {clf.best_params_}")
# print(f"Train Accuracy with best hyperparameters: {clf.best_score_:.4f}")
# print(f"Validation Accuracy with best hyperparameters: {clf.score(X_test, Y_test):.4f}")

# y_train_pred = clf.predict(X_train)
# y_test_pred = clf.predict(X_test)

# # Calculate performance metrics for Train data
# train_accuracy = accuracy_score(Y_train, y_train_pred)
# train_precision = precision_score(Y_train, y_train_pred, average='weighted')
# train_recall = recall_score(Y_train, y_train_pred, average='weighted')
# train_f1 = f1_score(Y_train, y_train_pred, average='weighted')

# # Calculate performance metrics for Test data
# accuracy = accuracy_score(Y_test, y_test_pred)
# precision = precision_score(Y_test, y_test_pred, average='weighted')
# recall = recall_score(Y_test, y_test_pred, average='weighted')
# f1 = f1_score(Y_test, y_test_pred, average='weighted')

# # Confusion matrix
# cm = confusion_matrix(Y_test, y_test_pred)
# plt.figure(figsize=(8, 6))
# sns.heatmap(cm, annot=True, cmap='Blues', fmt='g')
# plt.title('Decision Tree - Confusion Matrix (Tuned)')
# plt.xlabel('Predicted')
# plt.ylabel('Actual')
# plt.show()

# print(colored('Decision Tree - Train Metrics:', 'blue'))
# print(f'Train accuracy: {train_accuracy:.4f}')
# print(f'Train precision: {train_precision:.4f}')
# print(f'Train recall: {train_recall:.4f}')
# print(f'Train F1-score: {train_f1:.4f}')

# print(colored('Decision Tree - Test Metrics:', 'green'))
# print(f'Test accuracy: {accuracy:.4f}')
# print(f'Test precision: {precision:.4f}')
# print(f'Test recall: {recall:.4f}')
# print(f'Test F1-score: {f1:.4f}')

# %% [markdown]
# 

# %%


#joblib.dump(clf.best_estimator_, 'decision_tree_model.pkl')



# %%
#joblib.dump(label_encoder, 'label_encoder.pkl')

# %%
# import pandas as pd
# feature_names = ['has_ip', 'dot_count', 'www_count',
#     'at_count', 'directory_count', 'embedded_domain_count',
#     'suspicious_word', 'shortening_url', 'https_count', 'http_count',
#     'percent_count', 'question_count', 'dash_count', 'equal_count',
#     'url_length', 'hostname_length', 'first_directory_length', 'tld_length',
#     'digit_count', 'letter_count', 'abnormal_url']

# importances = pd.Series(clf.best_estimator_.feature_importances_, index=feature_names)
# print(importances.sort_values(ascending=False))

# %%
# sample = df[df['type'] == 'benign'].iloc[0]
# print(sample['url'])
# print(sample[feature_names].values)


