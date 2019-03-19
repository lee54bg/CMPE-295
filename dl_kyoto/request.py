
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

new_k26 = pd.get_dummies(ky26[['Label','Duration','Source bytes','Destination bytes',
              'Count','Same srv rate','Serror rate','Srv serror rate',
              'Dst host count','Dst host srv count','Dst host same src port rate',
              'Dst host serror rate','Dst host srv serror rate',             
              'Start Time','Service', 'Flag','Protocol']])

import numpy as np
from sklearn.utils import shuffle

# Extracting the benign and malicious data respectively
ky26_b = new_k26.loc[ky26['Label'] == 1]
ky26_m = new_k26.loc[ky26['Label'] == -1]

train_num = int(len(ky26_b) * 1.0)

df_balanced_m = ky26_m.take(np.random.permutation(len(ky26_m))[:train_num])
df_balanced_b = ky26_b

df_balanced = pd.concat([df_balanced_m, df_balanced_b])

df_balanced['Label'] = df_balanced['Label'] * (-1)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

x, y = df_balanced.iloc[:, 1:].values, df_balanced.iloc[:, 0].values

le = LabelEncoder()
y = le.fit_transform(y)

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2)

print("Printing X_train shape: {}".format(x_train.shape))
print("Printing X_test shape: {}".format(x_test.shape))
print("Printing y_train shape: {}".format(y_train.shape))
print("Printing y_test shape: {}".format(y_test.shape))

# # url = 'http://localhost:5000/api'

# # for data in X_test:
# #     print("{}".format(data.shape))
# #     new_data = np.expand_dims(data, 0)
    
# #     print("After expanding dimensions")
# #     print(new_data.shape)
    
# #     new_data = np.array(new_data).tolist()
# #     #print(new_data)

# #     #r = requests.post(url,json={'exp':new_data})
# #     #print(r.json())