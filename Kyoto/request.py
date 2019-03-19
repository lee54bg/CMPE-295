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

kyoto2006 = pd.read_csv('/home/seed/Desktop/Kyoto/20150101.csv',header=None)
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


for data in X_test:
    #np.array(data).reshape(1, -1)
    #data = np.array(data).tolist()
    data = np.array(data).tolist()
    print(data)
    r = requests.post(url,json={'test':data,})
    #print(r.json())

"""
Simple API call to send a request to the server
"""

"""
url = 'http://localhost:5000/api'

#r = requests.post(url,json={{'exp':2.5,}, {'exp':2.5,}})  # Does not work
r = requests.post(url,json={'exp':2.5,})

print(r.json())
"""

"""
url = 'http://localhost:5000/api'

# Importing the dataset
dataset = pd.read_csv('Salary_Data.csv')
X = dataset.iloc[:, :-1].values
y = dataset.iloc[:, 1].values

# Splitting the dataset into the Training set and Test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 1/3, random_state = 3)


print(type(X_test))
print(type(np.array(X_test).tolist()))
print(np.array(X_test).tolist())


for data in X_test:
    #np.array(data).reshape(1, -1)
    #data = np.array(data).tolist()
    data = np.array(data).tolist()
    print(data)
    r = requests.post(url,json={'exp':data,})
    print(r.json())
"""
