# Importing the libraries
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import pickle
import requests
import json


"""
Salary Data
"""

# Importing the dataset
dataset = pd.read_csv('Salary_Data.csv')
X = dataset.iloc[:, :-1].values
y = dataset.iloc[:, 1].values

# Splitting the dataset into the Training set and Test set
# The type of data that is being output is 'numpy.ndarray'
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 1/3, random_state = 0)


# Fitting Simple Linear Regression to the Training set
regressor = LinearRegression()
regressor.fit(X_train, y_train)

# Predicting the Test set results

y_pred = regressor.predict(X_test)
print(y_pred)


# for data in X_test:
#     print(type(data))
#     print(data)
#     print(np.array(data).reshape(1, -1))
#     print(data)
    
#     y_pred = regressor.predict(np.array(data).reshape(1, -1))
#     print(y_pred)

# Saving model to disk
pickle.dump(regressor, open('model.pkl','wb'))

# Loading model to compare the results
# model = pickle.load(open('model.pkl','rb'))

# Prints the result of the example model
# print(model.predict([[1.8]]))
