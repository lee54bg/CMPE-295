# Importing the libraries
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pickle
import requests
import json

kyoto2006 = pd.read_csv('dataset/20150101.csv',header=None)
kyoto2006.columns = ['Duration','Service', 'Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate','Flag',              
              'Label', 'Protocol','Start Time']

kyoto2006.drop(['Start Time', 'Flag'], axis=1)

kyoto2006 = pd.get_dummies (
    kyoto2006[['Label','Duration','Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate',             
              'Service', 'Protocol']]
    )

kyoto2006 = kyoto2006.loc[kyoto2006['Label'] != -2]

import numpy as np
from sklearn.utils import shuffle

kyoto2006_b = kyoto2006.loc[kyoto2006['Label'] == 1]
kyoto2006_m = kyoto2006.loc[kyoto2006['Label'] == -1]

train_number = int(len(kyoto2006_b) * 1.0)

df_balanced_m = kyoto2006_m.take(np.random.permutation(len(kyoto2006_m))[:train_number])
df_balanced_b = kyoto2006_b

df_balanced = pd.concat([df_balanced_m, df_balanced_b])
df_balanced = shuffle(df_balanced)
df_balanced['Label'] = df_balanced['Label'] * (-1)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

X, y = df_balanced.iloc[:, 1:].values, df_balanced.iloc[:, 0].values

le = LabelEncoder()
y = le.fit_transform(y)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

rfc = RandomForestClassifier(criterion='entropy', n_estimators=10, random_state=1, n_jobs=2)

rfc.fit(X_train, y_train)

# Saving model to disk
pickle.dump(rfc, open('models/model.pkl','wb'))
print("Model Trained")

# for test_x in X_test:
#     data = np.array(test_x).reshape(1, -1)
#     y_pred = rfc.predict(data).tolist()
#     print(type(y_pred))
#     print(y_pred)

# Regular Deep Learning Artificial Neural Network

import keras
from keras.models import Sequential
from keras.layers.core import Dense, Activation

model = Sequential()
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(50, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(10, input_dim=x.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(1,activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam')
model.fit(x_train, y_train, validation_data=(x_test,y_test), verbose=2, epochs=100)

# serialize model to JSON
model_json = model.to_json()
with open("models/model.json", "w") as json_file:
    json_file.write(model_json)

# serialize weights to HDF5
model.save_weights("models/model.h5")
print("Saved model to disk")

# Basic Autoencoder

# ae = Sequential()
# ae.add(Dense(21, kernel_initializer='normal', activation='relu')(x))
# ae.add(Dense(42, activation='sigmoid'))
# ae.compile(loss='mean_squared_error', optimizer='adam')
# ae.fit(x_train, y_train, validation_data=(x_test,y_test), verbose=2, epochs=50)