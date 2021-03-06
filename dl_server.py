# Import libraries
import numpy as np
from flask import Flask, request, jsonify
import json
import pickle
import tensorflow as tf
from keras.models import Sequential
from keras.layers import Dense
from keras.models import model_from_json

app = Flask(__name__)

def init():
    global loaded_model, graph

    # Load the model
    json_file = open('models/model.json', 'r')
    loaded_model_json = json_file.read()
    json_file.close()

    loaded_model = model_from_json(loaded_model_json)
    
    # load weights into new model
    loaded_model.load_weights("models/model.h5")
     
    # evaluate loaded model on test data
    loaded_model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    graph = tf.get_default_graph()

@app.route('/api',methods=['POST'])
def predict():
    # Get the data from the POST request.
    data = request.get_json(force=True)
    
    # Make prediction using model loaded from disk as per the data.
    load_data = np.asarray(data['exp'])
    
    with graph.as_default():
        prediction = loaded_model.predict_classes(load_data)
    
    result = np.array(prediction).tolist()
    
    return jsonify(result)

if __name__ == '__main__':
    init()
    app.run(port=5000, debug=True, threaded=True)