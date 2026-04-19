from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import joblib
import os
from predict import PredictPipeline

app = Flask(__name__)


# load the model

model = joblib.load('model/decision_tree_model.pkl')

# print(model)
pred = PredictPipeline()

# Enable CORS with all origins
cors = CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/", methods=['GET'])
def index():
    return "<h1>Hello World!</h1>"

@app.route('/api/check_link', methods=['POST'])
@cross_origin()
def predict():
    
    url = request.json['url']
    print("URL: " + url)
    
    transform_url = pred.transformURL(url)

    transform_url = transform_url

    print("transform_url" , transform_url)

    prediction = pred.predict(transform_url)
    
    # 'benign', 'defacement','phishing','malware'
    if(prediction == 0):
        res = 'benign'
    elif(prediction == 1):
        res = 'defacement'
    elif(prediction == 2):
        res = 'phishing'
    else:
        res = 'malware'

    print("Prediction: ", prediction[0])
    response = jsonify({'prediction': res})
    
    return response

if __name__ == '__main__':
   app.run()