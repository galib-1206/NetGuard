import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
import sklearn
import imblearn
import sys

# Ignore warnings
import warnings
warnings.filterwarnings('ignore')

# Settings
pd.set_option('display.max_columns', None)
np.set_printoptions(threshold=sys.maxsize)
np.set_printoptions(precision=3)
sns.set(style="darkgrid")
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 12
plt.rcParams['ytick.labelsize'] = 12

# print("pandas : {0}".format(pd.__version__))
# print("numpy : {0}".format(np.__version__))
# print("matplotlib : {0}".format(matplotlib.__version__))
# print("seaborn : {0}".format(sns.__version__))
# print("sklearn : {0}".format(sklearn.__version__)) 
# print("imblearn : {0}".format(imblearn.__version__)) 

# Dataset field names
datacols = ["duration", "protocol_type", "service", "src_bytes",
            "dst_bytes", "land", "wrong_fragment", "urgent", "attack"]

# Load NSL_KDD train dataset
dfkdd_train = pd.read_table("KDDTrain.csv", sep=",")
# dfkdd_train = dfkdd_train.iloc[:,:-1] # removes an unwanted extra field

# Load NSL_KDD test dataset
dfkdd_test = pd.read_table("KDDTest.csv", sep=",")
# dfkdd_test = dfkdd_test.iloc[:,:-1]  

real_data = pd.read_csv('/home/bs00794/Documents/My_Projects/netprobe_lite/models/captured_packets.csv')

real_data = real_data[datacols[:-1]]       
dfkdd_test = dfkdd_test[datacols]
dfkdd_train = dfkdd_train[datacols]
real_data.head(3)

# Map attack types to a more meaningful label
mapping = {
    'ipsweep': 'Probe', 'satan': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'saint': 'Probe', 'mscan': 'Probe',
    'teardrop': 'DoS', 'pod': 'DoS', 'land': 'DoS', 'back': 'DoS', 'neptune': 'DoS', 'smurf': 'DoS', 'mailbomb': 'DoS',
    'udpstorm': 'DoS', 'apache2': 'DoS', 'processtable': 'DoS',
    'perl': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'buffer_overflow': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
    'sqlattack': 'U2R', 'httptunnel': 'U2R',
    'ftp_write': 'R2L', 'phf': 'R2L', 'guess_passwd': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'imap': 'R2L',
    'spy': 'R2L', 'multihop': 'R2L', 'named': 'R2L', 'snmpguess': 'R2L', 'worm': 'R2L', 'snmpgetattack': 'R2L',
    'xsnoop': 'R2L', 'xlock': 'R2L', 'sendmail': 'R2L',
    'normal': 'Normal'
}

# Drop rows where attack type is 'attack' and apply attack class mappings to dataset
dfkdd_train.drop(dfkdd_train[dfkdd_train['attack']=='attack'].index, axis=0, inplace=True)
dfkdd_test.drop(dfkdd_test[dfkdd_test['attack']=='attack'].index, axis=0, inplace=True)

dfkdd_train['attack_class'] = dfkdd_train['attack'].apply(lambda v: mapping[v])
dfkdd_train.drop(['attack'], axis=1, inplace=True)
dfkdd_test['attack_class'] = dfkdd_test['attack'].apply(lambda v: mapping[v])
dfkdd_test.drop(['attack'], axis=1, inplace=True)

# Attack Class Distribution
attack_class_freq_train = dfkdd_train[['attack_class']].apply(lambda x: x.value_counts())
attack_class_freq_test = dfkdd_test[['attack_class']].apply(lambda x: x.value_counts())

attack_class_freq_train['frequency_percent_train'] = round((100 * attack_class_freq_train / attack_class_freq_train.sum()), 2)
attack_class_freq_test['frequency_percent_test'] = round((100 * attack_class_freq_test / attack_class_freq_test.sum()), 2)

attack_class_dist = pd.concat([attack_class_freq_train, attack_class_freq_test], axis=1)
attack_class_dist

# Convert columns to numeric where possible
for col in dfkdd_train.columns:
    dfkdd_train[col] = pd.to_numeric(dfkdd_train[col], errors='ignore')

for col in dfkdd_test.columns:
    dfkdd_test[col] = pd.to_numeric(dfkdd_test[col], errors='ignore')

real_data.dropna(axis=0, inplace=True)

# Normalize the numerical columns using StandardScaler

from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()

cols = dfkdd_train.select_dtypes(include=['float64', 'int64']).columns
sc_train = scaler.fit_transform(dfkdd_train.select_dtypes(include=['float64', 'int64']))
sc_test = scaler.transform(dfkdd_test.select_dtypes(include=['float64', 'int64']))
sc_real = scaler.transform(real_data.select_dtypes(include=['float64', 'int64']))

sc_traindf = pd.DataFrame(sc_train, columns=cols)
sc_testdf = pd.DataFrame(sc_test, columns=cols)
sc_realdf = pd.DataFrame(sc_real, columns=cols)

# Encoding categorical attributes
from sklearn.preprocessing import LabelEncoder
encoder = LabelEncoder()

cattrain = dfkdd_train.select_dtypes(include=['object']).copy()
cattest = dfkdd_test.select_dtypes(include=['object']).copy()
catreal = real_data.select_dtypes(include=['object']).copy()

traincat = cattrain.apply(encoder.fit_transform)
testcat = cattest.apply(encoder.fit_transform)
realcat = catreal.apply(encoder.fit_transform)

enctrain = traincat.drop(['attack_class'], axis=1)
enctest = testcat.drop(['attack_class'], axis=1)

cat_Ytrain = traincat[['attack_class']].copy()
cat_Ytest = testcat[['attack_class']].copy()

# Over-sample the dataset using RandomOverSampler

from imblearn.over_sampling import RandomOverSampler
from collections import Counter

sc_traindf = dfkdd_train.select_dtypes(include=['float64', 'int64'])
refclasscol = pd.concat([sc_traindf, enctrain], axis=1).columns
refclass = np.concatenate((sc_train, enctrain.values), axis=1)
X = refclass

c, r = cat_Ytest.values.shape
y_test = cat_Ytest.values.reshape(c,)

c, r = cat_Ytrain.values.shape
y = cat_Ytrain.values.reshape(c,)

ros = RandomOverSampler(random_state=42)
X_res, y_res = ros.fit_resample(X, y)
print('Original dataset shape {}'.format(Counter(y)))
print('Resampled dataset shape {}'.format(Counter(y_res)))

# Train RandomForestClassifier

from sklearn.ensemble import RandomForestClassifier
rfc = RandomForestClassifier(max_depth=2, random_state=0)

X_res, y_res = X, y

rfc.fit(X_res, y_res)

# Feature Importance
score = np.round(rfc.feature_importances_, 3)
importances = pd.DataFrame({'feature': refclasscol, 'importance': score})
importances = importances.sort_values('importance', ascending=False).set_index('feature')

# Plot feature importance
plt.rcParams['figure.figsize'] = (11, 4)
importances.plot.bar()

# Feature Selection with RFE
from sklearn.feature_selection import RFE
import itertools

rfe = RFE(rfc, n_features_to_select=6)
rfe = rfe.fit(X_res, y_res)

feature_map = [(i, v) for i, v in itertools.zip_longest(rfe.get_support(), refclasscol)]
selected_features = [v for i, v in feature_map if i == True]

# Prepare train and test data
newcol = list(refclasscol)
newcol.append('attack_class')

new_y_res = y_res[:, np.newaxis]
res_arr = np.concatenate((X_res, new_y_res), axis=1)
res_df = pd.DataFrame(res_arr, columns=newcol)

reftest = pd.concat([sc_testdf, testcat], axis=1)
refreal = pd.concat([sc_realdf, realcat], axis=1)
reftest['attack_class'] = reftest['attack_class'].astype(np.float64)
reftest['protocol_type'] = reftest['protocol_type'].astype(np.float64)
refreal['protocol_type'] = refreal['protocol_type'].astype(np.float64)
reftest['service'] = reftest['service'].astype(np.float64)
refreal['service'] = refreal['service'].astype(np.float64)

res_df.shape
print(reftest.shape)
print(refreal.shape)

import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder
from collections import defaultdict
from sklearn.svm import SVC
from sklearn.naive_bayes import BernoulliNB
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier
from sklearn import metrics
import joblib


from collections import defaultdict
classdict = defaultdict(list)

# Define data and necessary variables
attacklist = [('DoS', 0.0), ('Probe', 2.0), ('R2L', 3.0), ('U2R', 4.0)]
normalclass = [('Normal', 1.0)]
classdict = defaultdict(list)

# Subdivide train and test datasets into two-class attack labels
def create_classdict():
    '''This function subdivides train and test dataset into two-class attack labels'''
    for j, k in normalclass: 
        for i, v in attacklist: 
            restrain_set = res_df.loc[(res_df['attack_class'] == k) | (res_df['attack_class'] == v)]
            classdict[j +'_' + i].append(restrain_set)
            # test labels
            reftest_set = reftest.loc[(reftest['attack_class'] == k) | (reftest['attack_class'] == v)]
            classdict[j +'_' + i].append(reftest_set)
        
create_classdict()

# Extract and print class dict keys
for k, v in classdict.items():
    print(k)

pretrain = classdict['Normal_DoS'][0]
pretest = classdict['Normal_DoS'][1]
grpclass = 'Normal_DoS'

# OneHotEncoder setup
enc = OneHotEncoder(handle_unknown='ignore')

# Prepare data
Xresdf = pretrain 
newtest = pretest


Xresdfnew = Xresdf[selected_features]
Xresdfnum = Xresdfnew.drop(['service'], axis=1)
Xresdfcat = Xresdfnew[['service']].copy()

Xtest_features = newtest[selected_features]
Xtestdfnum = Xtest_features.drop(['service'], axis=1)
Xtestcat = Xtest_features[['service']].copy()

Xreal_features = refreal[selected_features]
Xrealdfnum = Xreal_features.drop(['service'], axis=1)
Xrealcat = Xreal_features[['service']].copy()

# Fit train data
enc.fit(Xresdfcat)

# Transform train, test, and real data
X_train_1hotenc = enc.transform(Xresdfcat).toarray()
X_test_1hotenc = enc.transform(Xtestcat).toarray()
X_real_1hotenc = enc.transform(Xrealcat).toarray()

# Concatenate numerical and categorical features
X_train = np.concatenate((Xresdfnum.values, X_train_1hotenc), axis=1)
X_test = np.concatenate((Xtestdfnum.values, X_test_1hotenc), axis=1) 
X_real = np.concatenate((Xrealdfnum.values, X_real_1hotenc), axis=1)

# Prepare labels for train and test data
y_train = Xresdf[['attack_class']].copy()
c, r = y_train.values.shape
Y_train = y_train.values.reshape(c,)

y_test = newtest[['attack_class']].copy()
c, r = y_test.values.shape 
Y_test = y_test.values.reshape(c,)





# Train different models
models = []

# Uncomment or comment as needed
# KNN_Classifier = KNeighborsClassifier(n_jobs=-1)
# models.append(('KNeighborsClassifier', KNN_Classifier))
# LogisticRegression and other classifiers

# Train KNeighborsClassifier Model
KNN_Classifier = KNeighborsClassifier(n_jobs=-1)
KNN_Classifier.fit(X_train, Y_train); 
# models.append(('KNeighborsClassifier', KNN_Classifier))

LGR_Classifier = LogisticRegression(n_jobs=-1, random_state=0)
LGR_Classifier.fit(X_train, Y_train)
# models.append(('LogisticRegression', LGR_Classifier))

BNB_Classifier = BernoulliNB()
BNB_Classifier.fit(X_train, Y_train)
# models.append(('Naive Baye Classifier', BNB_Classifier))

DTC_Classifier = tree.DecisionTreeClassifier(criterion='entropy', random_state=0)
DTC_Classifier.fit(X_train, Y_train)
models.append(('Decision Tree Classifier', DTC_Classifier))

# Evaluate models
for i, v in models:
    scores = cross_val_score(v, X_train, Y_train, cv=10)
    accuracy = metrics.accuracy_score(Y_train, v.predict(X_train))
    confusion_matrix = metrics.confusion_matrix(Y_train, v.predict(X_train))
    classification = metrics.classification_report(Y_train, v.predict(X_train))
    
    # print(f'============================== {grpclass} {i} Model Evaluation ==============================\n')
    # print(f"Cross Validation Mean Score:\n {scores.mean()}")
    # print(f"Model Accuracy:\n {accuracy}")
    # print(f"Confusion matrix:\n {confusion_matrix}")
    # print(f"Classification report:\n {classification}\n")









import joblib
import os

# Save the trained Decision Tree Classifier model

model_path = os.path.join(os.path.dirname(__file__), "anomaly_detection_model.pkl")

joblib.dump(DTC_Classifier, "anomaly_detection_model.pkl")

# Load the saved model from the same directory

model = joblib.load(model_path)



# Load the model
model = joblib.load("anomaly_detection_model.pkl")  # Adjust path if necessary

# Print model details
print(model)

# Test models on test data
for i, v in models:
    accuracy = metrics.accuracy_score(Y_test, v.predict(X_test))
    confusion_matrix = metrics.confusion_matrix(Y_test, v.predict(X_test))
    classification = metrics.classification_report(Y_test, v.predict(X_test))
    print(f'============================== {grpclass} {i} Model Test Results ==============================\n')
    print(f"Model Accuracy:\n {accuracy}")
    print(f"Confusion matrix:\n {confusion_matrix}")
    print(f"Classification report:\n {classification}\n")

# Predict using real data
for i, v in models:
    res = v.predict(X_real)

print("---JSON-RESULT---")

import json

# Predict using real data
results = {}
for i, v in models:
    res = v.predict(X_real)
    results[i] = res.tolist()  # Convert numpy array to list for JSON serialization

# Print results as JSON
print(json.dumps(results))