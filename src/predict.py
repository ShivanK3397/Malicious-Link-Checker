import sys
import pandas as pd
from src.exception import customException
from src.utils import load_object
import os
import numpy as np
from pathlib import Path
import googlesearch

MODEL_DIR = Path(__file__).resolve().parent.parent / "model"
MODELS_DIR = Path(__file__).resolve().parent.parent / "models" 

from src.transform import transformationFunctions

class PredictPipeline:
    def __init__(self):
        pass

    def transformURL(self, url):
        try:
            obj = transformationFunctions()
            use_of_ip = obj.has_ip_address(url)
            abnormal_url = obj.abnormal_url(url)
            google_index = obj.google_index(url)
            countDot = obj.count_dot(url)
            countWWW = obj.count_www(url)
            countATR = obj.count_at(url)
            count_dir= obj.count_directory(url)
            count_embed_domain = obj.count_embedded_domain(url)
            short_url = obj.shortening_url(url)
            countPercentage = obj.count_percent(url)
            countQUES = obj.count_question(url)
            countHyphen = obj.count_dash(url)
            countEqual = obj.count_equal(url)
            url_length = obj.url_length(url)
            count_https = obj.count_https(url)
            count_http = 0
            hostname_length = obj.hostname_length(url)
            sus_url = obj.suspicious_words(url)
            fd_length = obj.first_directory_length(url)
            tld_length = obj.top_level_domain_length(url)
            count_digits = obj.count_digits(url)
            count_letters = obj.count_letters(url)

            

            ls = [use_of_ip,
            abnormal_url,
            google_index,
            countDot,
            countWWW,
            countATR,
            count_dir,
            count_embed_domain,
            short_url,
            countPercentage,
            countQUES,
            countHyphen,
            countEqual,
            url_length,
            count_https ,
            count_http,
            hostname_length,
            sus_url,
            fd_length,
            tld_length,
            count_digits,
            count_letters]

            arr = np.array(ls)

            return arr
            # return  custom_data_input_dict.values()

        except Exception as e:
            raise customException(e,sys)
        
    def predict(self,features):
        try:
            model_path=os.path.join(MODEL_DIR, "model.pkl")
            preprocessor_path=os.path.join(MODELS_DIR, "preprocessor.pkl")
            print("Before Loading")
            model=load_object(file_path=model_path)
            preprocessor=load_object(file_path=preprocessor_path)
            print("After Loading")
            data_scaled=preprocessor.transform(features)
            preds=model.predict(data_scaled)
            return preds
        
        except Exception as e:
            raise customException(e,sys)

