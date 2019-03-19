# Importing the libraries

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pickle
import requests
import json
import requests

# Load the Kyoto 2006 Dataset
ky26 = pd.read_csv('20150101.csv',header=None)

# Provide columns for the Kyoto Dataset
ky26.columns = ['Duration','Service', 'Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate','Flag',              
              'Label',
              'Protocol','Start Time']

# Removing the unknown attacks
ky26 = ky26.loc[ky26['Label'] != -2]

# Encode the data first so that all categorical values are numerized
new_k26 = pd.get_dummies(ky26[['Label','Duration','Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate',             
              'Start Time','Service', 'Flag','Protocol']])

import numpy as np
from sklearn.utils import shuffle

# Extracting the benign and malicious data respectively
kyoto_benign = new_k26.loc[ky26['Label'] == 1]
kyoto_malicious = new_k26.loc[ky26['Label'] == -1]

train_num = int(len(kyoto_benign) * 1.0)

traf_mal = kyoto_malicious.take(np.random.permutation(len(kyoto_malicious))[:train_num])
traf_benign = kyoto_benign

processed_data = pd.concat([traf_mal, traf_benign])

processed_data['Label'] = processed_data['Label'] * (-1)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

x, y = processed_data.iloc[:, 1:].values, processed_data.iloc[:, 0].values

le = LabelEncoder()
y = le.fit_transform(y)

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2)

# Regular deep learning artificial neural network

import keras
from keras.models import Sequential
from keras.layers.core import Dense, Activation

model = Sequential()
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(50, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(1,activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam')
model.fit(x_train, y_train, validation_data=(x_test,y_test), verbose=2, epochs=2)

# for data in x_test:
#   new_data = np.expand_dims(data, 0)
#   print(new_data)
#   print(type(new_data))
#   y_pred = model.predict_classes(new_data)
#   print(y_pred)
#   break

# serialize model to JSON
model_json = model.to_json()
with open("nn/model.json", "w") as json_file:
    json_file.write(model_json)

# serialize weights to HDF5
model.save_weights("nn/model.h5")
print("Saved model to disk")

# import keras
# from keras.models import Sequential
# from keras.layers.core import Dense, Activation

# ae = Sequential()
# ae.add(Dense(21, input_dim=X.shape[1], activation='relu'))
# ae.add(Dense(X.shape[1], activation='sigmoid'))
# ae.compile(loss='binary_crossentropy', optimizer='adam')
# ae.fit(X_train, y_train, validation_data=(X_test,y_test), verbose=2, epochs=50)