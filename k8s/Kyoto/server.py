# Import libraries
import numpy as np
from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

# Load the model
model = pickle.load(open('model.pkl','rb'))

@app.route('/api',methods=['POST'])
def predict():
    # Get the data from the POST request.
    data = request.get_json(force=True)
    
    print(type(data))

    # Make prediction using model loaded from disk as per the data.
    #load_data = [[np.array(data['exp'])]]
    #load_data = [np.array(data['exp'])]
    load_data = [np.array(data['test'])]
    
    print(type(load_data))
    print(load_data)
    
    prediction = model.predict(load_data)
    print(type(prediction))
    print(prediction)
    
    # Take the first value of prediction
    output = prediction
    return jsonify(output)

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000, debug=True)