from dataclasses import dataclass
from pathlib import Path
import numpy as np
import pandas as pd
import os
import sys
from exception import customException
from logger import logging
from sklearn.model_selection import train_test_split



from data_transform import DataTransformation
from data_transform import DataTransformationConfig

from model import ModelTrainerConfig
from model import ModelTrainer

BASE_DIR = Path(__file__).resolve().parent.parent  # project root


@dataclass
class DataIngestionConfig:
    train_data_path: str = str(BASE_DIR / "models" / "train.csv")
    test_data_path: str = str(BASE_DIR / "models" / "test.csv")
    raw_data_path: str = str(BASE_DIR / "models" / "raw.csv")
    source_data_path: str = str(BASE_DIR / "data" / "preprocessed_data.csv")

class DataIngestion:
    def __init__(self):
        self.ingestion_config = DataIngestionConfig()
    
    def initiate_data_ingestion(self):
        logging.info("Entered the data ingestion method or component")
        try:
            df = pd.read_csv(self.ingestion_config.source_data_path)

            logging.info('Read the dataset as DataFrame')

            os.makedirs(os.path.dirname(self.ingestion_config.train_data_path), exist_ok=True)

            df.to_csv(self.ingestion_config.raw_data_path,index=False,header=True)

            logging.info("Train test split initiated")

            train_set, test_set = train_test_split(df, test_size=0.2, shuffle = True, random_state=42)

            train_set.to_csv(self.ingestion_config.train_data_path, index=False, header=True)

            test_set.to_csv(self.ingestion_config.test_data_path, index=False, header=True)

            logging.info("Ingestion of the data is completed")

            return(
                self.ingestion_config.train_data_path,
                self.ingestion_config.test_data_path
            )

        except Exception as e:
            raise customException(e,sys)
        

if __name__=="__main__":
    obj = DataIngestion()
    train_data,test_data = obj.initiate_data_ingestion()

    data_transformation = DataTransformation()
    train_arr, test_arr, _ = data_transformation.initiate_data_transformation(train_data,test_data)

    model_trainer = ModelTrainer()
    print(model_trainer.initiate_model_trainer(train_arr,test_arr))