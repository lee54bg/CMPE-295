import pandas as pd
import numpy as np

df = pd.read_csv('AWID-ATK-R-Trn/1.csv', header=0)
df = df.drop(df.columns[0], axis=1)
df = df.drop(columns=["wlan_fc_retry", "wlan_fc_type", "wlan_fc_subtype", 'wlan_fc_ds', 'wlan_fc_frag', 'data_len'])
df = df.fillna(0)

df = pd.get_dummies(df, prefix=["classification"], 
    columns=["classification"])

# Adjust this statement in case you need to include or disclude features
x, y = df.iloc[:, 0:2].values, df.iloc[:, 2:12].values

from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=0)

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

rfc = RandomForestClassifier(criterion='entropy', n_estimators=10, random_state=1, n_jobs=2)

rfc.fit(x_train, y_train)

import pickle

# Saving model to disk
pickle.dump(rfc, open('model.pkl','wb'))
print("Model Trained")