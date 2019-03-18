
# Importing the libraries
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pickle

"""
Kyoto Dataset analysis
"""

kyoto2006 = pd.read_csv('20150101.csv',header=None)
kyoto2006.columns = ['Duration','Service', 'Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate','Flag',              
              'Label',
              'Protocol','Start Time']

# Count the number of unknown attacks
kyoto2006 = kyoto2006.loc[kyoto2006['Label'] != -2]
kyoto2006.Label.value_counts()

import numpy as np
from sklearn.utils import shuffle

# Take the number of malicious or benign traffic and put them in their own dataset
kyoto2006_b = kyoto2006.loc[kyoto2006['Label'] == 1]
kyoto2006_m = kyoto2006.loc[kyoto2006['Label'] == -1]

train_number = int(len(kyoto2006_b) * 1.0)
print()

df_balanced_m = kyoto2006_m.take(np.random.permutation(len(kyoto2006_m))[:train_number])
df_balanced_b = kyoto2006_b

# Combine the two lists together
df_balanced = pd.concat([df_balanced_m, df_balanced_b])
# Shuffle the data
df_balanced = shuffle(df_balanced)
df_balanced['Label'] = df_balanced['Label'] * (-1)
df_balanced.Label.value_counts()

df = pd.get_dummies (df_balanced[['Label','Duration','Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate',             
              'Start Time','Service', 'Flag','Protocol']]
    )


from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

X, y = df.iloc[:, 1:].values, df.iloc[:, 0].values

le = LabelEncoder()
y = le.fit_transform(y)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)


# Regular deep learning artificial neural network

import keras
from keras.models import Sequential
from keras.layers.core import Dense, Activation

model = Sequential()
model.add(Dense(10, input_dim=X.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(50, input_dim=X.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(10, input_dim=X.shape[1], kernel_initializer='normal', activation='relu'))
model.add(Dense(1,activation='sigmoid'))
model.compile(loss='binary_crossentropy', optimizer='adam')
model.fit(X_train, y_train, validation_data=(X_test,y_test), verbose=2, epochs=2)
#model.fit(X_train, y_train, batch_size=1, verbose=2, epochs=2)

# y_pred = model.predict(X_test)
# print(y_pred)

for data in X_test:
  new_data = np.expand_dims(data, 0)
  print(new_data)
  print(type(new_data))
  y_pred = model.predict_classes(new_data)
  #np.expand_dims(a, 0)
  #y_pred = model.predict_classes(np.array(data).reshape(-1, 1))
  print(y_pred)
  break
  # print(type(data))
  # print(data)
  # print(data.shape)
  # break

# # serialize model to JSON
# model_json = model.to_json()
# with open("model.json", "w") as json_file:
#     json_file.write(model_json)

# # serialize weights to HDF5
# model.save_weights("model.h5")
# print("Saved model to disk")

# import keras
# from keras.models import Sequential
# from keras.layers.core import Dense, Activation

# ae = Sequential()
# ae.add(Dense(21, input_dim=X.shape[1], activation='relu'))
# ae.add(Dense(X.shape[1], activation='sigmoid'))
# ae.compile(loss='binary_crossentropy', optimizer='adam')
# ae.fit(X_train, y_train, validation_data=(X_test,y_test), verbose=2, epochs=50)