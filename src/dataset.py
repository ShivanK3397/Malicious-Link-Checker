import numpy as np
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from model import ModelTrainer  
from transform import transformationFunctions  

# 1. Load your dataset
BASE_DIR = Path(__file__).resolve().parent.parent
csv_path = BASE_DIR / "model" / "malicious_phish.csv"

df = pd.read_csv(csv_path)

# 2. Separate features and target
X = df.drop(columns=["target_column"])   # replace with your label column name
y = df["target_column"]

# 3. Split into train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Stack into arrays (last column = label, as the code expects)
train_array = np.c_[X_train, y_train]
test_array  = np.c_[X_test,  y_test]

# 6. Run the trainer
trainer = ModelTrainer()
trainer.initiate_model_trainer(train_array, test_array)