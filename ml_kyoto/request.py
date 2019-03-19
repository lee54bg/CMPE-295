
# Importing the libraries
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pickle
import requests
import json
import requests

"""
Kyoto Dataset analysis
"""
# Load the Kyoto 2006 Dataset
kyoto2006 = pd.read_csv('20150101.csv',header=None)
# Provide columns for the Kyoto Dataset
kyoto2006.columns = ['Duration','Service', 'Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate','Flag',              
              'Label',
              'Protocol','Start Time']

kyoto2006 = kyoto2006.loc[kyoto2006['Label'] != -2]
kyoto2006.Label.value_counts()

import numpy as np
from sklearn.utils import shuffle

kyoto2006_b = kyoto2006.loc[kyoto2006['Label'] == 1]
kyoto2006_m = kyoto2006.loc[kyoto2006['Label'] == -1]

train_number = int(len(kyoto2006_b) * 1.0)
df_balanced_m = kyoto2006_m.take(np.random.permutation(len(kyoto2006_m))[:train_number])
df_balanced_b = kyoto2006_b

df_balanced = pd.concat([df_balanced_m, df_balanced_b])
df_balanced = shuffle(df_balanced)
df_balanced['Label'] = df_balanced['Label']* (-1)
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

url = 'http://10.111.188.30:8080/api'

for data in X_test:
    data = np.array(data).tolist()
    r = requests.post(url,json={'exp':data})
    
    print(r.json())
