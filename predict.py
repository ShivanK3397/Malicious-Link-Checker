import sys
import joblib
import pandas as pd

from transform import customException

import os
import numpy as np

from transform import transformationFunctions

class PredictPipeline:
    def __init__(self):
        pass

    def transformURL(self, url):
        
        try:
            obj = transformationFunctions()
            has_ip = obj.has_ip_address(url)
            in_google_index = 0
            dot_count = obj.count_dot(url)
            www_count = obj.count_www(url)
            at_count = obj.count_at(url)
            directory_count = obj.count_directory(url)
            embedded_domain_count = obj.count_embedded_domain(url)
            suspicious_word = obj.suspicious_words(url)
            shortening_url = obj.shortening_url(url)
            https_count = obj.count_https(url)
            http_count = obj.count_http(url)
            percent_count = obj.count_percent(url)
            question_count = obj.count_question(url)
            dash_count = obj.count_dash(url)
            equal_count = obj.count_equal(url)
            url_length = obj.url_length(url)
            hostname_length = obj.hostname_length(url) 
            first_directory_length = obj.first_directory_length(url)
            tld_length = obj.top_level_domain_length(url)
            digit_count = obj.count_digits(url)
            letter_count = obj.count_letters(url)
            abnormal_url = obj.abnormal_url(url)



            ls = [has_ip,
            in_google_index,
            dot_count,
            www_count,
            at_count,
            directory_count,
            embedded_domain_count,
            suspicious_word,
            shortening_url,
            https_count,
            http_count,
            percent_count,
            question_count,
            dash_count,
            equal_count,
            url_length,
            
            hostname_length,
            first_directory_length,
            tld_length,
            digit_count,
            letter_count,
            abnormal_url]

            arr = np.array(ls)

            return arr
            # return  custom_data_input_dict.values()

        except Exception as e:
            raise customException(e,sys)
        
    def predict(self,features):
        try:
           
            print("Before Loading")
            model = joblib.load('model/decision_tree_model.pkl')
            label_encoder = joblib.load('model/label_encoder.pkl')
            print("After Loading")

            feature_names = [
            'has_ip', 'in_google_index', 'dot_count', 'www_count',
            'at_count', 'directory_count', 'embedded_domain_count',
            'suspicious_word','shortening_url', 'https_count',
            'http_count', 'percent_count', 'question_count',
            'dash_count', 'equal_count', 'url_length',  'hostname_length',
            'first_directory_length', 'tld_length', 'digit_count',
            'letter_count', 'abnormal_url'
            ]

    


            features_df = pd.DataFrame([features], columns=feature_names)

            print("Feature values:")
            for col in feature_names:
                print(f"  {col}: {features_df[col].values[0]}")
            print(f"Feature shape: {features_df.shape}")
            print(f"Label encoder classes: {label_encoder.classes_}")
            
            preds = model.predict(features_df)
            print(f"Raw prediction: {preds}")
            print(f"Decoded prediction: {label_encoder.inverse_transform(preds)[0]}")
        
            return label_encoder.inverse_transform(preds)[0]
        
        except Exception as e:
            raise customException(e,sys)
        

