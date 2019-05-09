# Importing the libraries
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pickle
import requests
import json

def load_data(path):
    kyoto2006 = pd.read_csv(path,header=None)
    kyoto2006.columns = ['Duration','Service', 'Source bytes','Destination bytes',
                  'Count','Same srv rate','Serror rate','Srv serror rate',
                  'Dst host count','Dst host srv count','Dst host same src port rate',
                  'Dst host serror rate','Dst host srv serror rate','Flag',              
                  'Label', 'Protocol','Start Time']

    kyoto2006.drop(['Start Time', 'Flag'], axis=1)

    return kyoto2006

def preprocess(kyoto2006):
    kyoto2006 = pd.get_dummies (kyoto2006[['Label','Duration','Source bytes','Destination bytes',
                  'Count','Same srv rate','Serror rate','Srv serror rate',
                  'Dst host count','Dst host srv count','Dst host same src port rate',
                  'Dst host serror rate','Dst host srv serror rate',             
                  'Service', 'Protocol']])

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

    x, y = df_balanced.iloc[:, 1:].values, df_balanced.iloc[:, 0].values

    le = LabelEncoder()
    y = le.fit_transform(y)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=1)

    return x, y, x_train, x_test, y_train, y_test

def ml_train(x, y, x_train, x_test, y_train, y_test):
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

    from sklearn.linear_model import LogisticRegression
    lr = LogisticRegression()
    lr.fit(x_train, y_train)

    # rfc = RandomForestClassifier(criterion='entropy', n_estimators=10, random_state=1, n_jobs=2)
    # rfc.fit(x_train, y_train)
    
    # Saving model to disk
    pickle.dump(lr, open('models/model.pkl','wb'))
    print("Model Trained")

# Regular Deep Learning Artificial Neural Network

def dl_train(x, y, x_train, x_test, y_train, y_test):
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

if __name__ == "__main__":
    path = "dataset/20150101.csv"
    
    kyoto2006 = load_data(path)

    x, y, x_train, x_test, y_train, y_test = preprocess(kyoto2006)

    # ml_train(x, y, x_train, x_test, y_train, y_test)
    dl_train(x, y, x_train, x_test, y_train, y_test)