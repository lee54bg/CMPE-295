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
Simple API call to send a request to the server
"""

# url = 'http://localhost:5000/api'

# r = requests.post(url,json={'exp':2.5,})

# print(r.json())

url = 'http://localhost:5000/api'

# Importing the dataset
dataset = pd.read_csv('Salary_Data.csv')
X = dataset.iloc[:, :-1].values
y = dataset.iloc[:, 1].values

# Splitting the dataset into the Training set and Test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 1/3, random_state = 3)

"""
# Output:  <class 'numpy.ndarray'>
print(type(X_test))

# Output:  <class 'list'>
print(type(np.array(X_test).tolist()))

# Output:  [[4.9], [2.9], [7.9], [9.5], [5.9], [4.5], [4.1], [1.5], [5.1], [1.3]]
print(np.array(X_test).tolist())
"""

for data in X_test:
    """
    # <class 'numpy.ndarray'>
    print(type(data))
    
    # [4.9]
    print(data)
    """
    item = np.array(data).tolist()

    # <class 'list'>
    print(type(item))
    
    # Example output: [1.3]
    print(item)

    r = requests.post(url,json={'exp':item})
    print(r.json())