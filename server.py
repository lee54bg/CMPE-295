# Import libraries
import numpy as np
from flask import Flask, request, jsonify
import json
import pickle

app = Flask(__name__)

# Load the model
model = pickle.load(open('models/model.pkl','rb'))

@app.route('/api',methods=['POST'])
def predict():
    # Get the data from the POST request.
    data = request.get_json(force=True)
    
    # Make prediction using model loaded from disk as per the data.
    load_data = [data['exp']]
    
    # Take our loaded data and perform the prediction
    prediction = model.predict(load_data)
    
    print(prediction)

    # Take the first value of prediction
    output = np.array(prediction).tolist()
    
    return jsonify(output)

if __name__ == '__main__':
    app.run(host='127.0.0.1',port=5000, debug=True)