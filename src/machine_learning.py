import pandas as pd
from sklearn.svm import SVC
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.metrics import mean_squared_error
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest
import random

def split_training_testing(ratio_training, data, onlyFeatures=True):
    result = {
        "training_tags":[],
        "training_features":[],
        "testing_tags":[],
        "testing_features":[]
    }

    num_training_elems = round(len(data) * ratio_training)
    for index,elem in data.iterrows():
        row = {
            "tag":None,
            "features":[]
        }

        for tag, i in elem.iteritems():
            if tag == 'malicious':
                row["tag"] = i
            elif tag[:2] == "f_" or not onlyFeatures:
                row["features"].append(i)

        if len(result["training_tags"]) >= num_training_elems:
            result["testing_features"].append(row["features"])
            result["testing_tags"].append(row["tag"])
        else:
            result["training_features"].append(row["features"])
            result["training_tags"].append(row["tag"])

    return result

def GBT(fileName):
    print("Running GBT...")
    data = load_file(fileName)
    split_data = split_training_testing(0.7, data)

    clf = GradientBoostingRegressor()
    return fit_and_predict(clf, split_data)

def RF(fileName):
    print("Running Random Forest...")
    data = load_file(fileName)
    split_data = split_training_testing(0.7, data)

    clf = RandomForestClassifier(n_estimators=100)
    return fit_and_predict(clf, split_data)

def SVM(fileName):
    print("Running SVM...")
    data = load_file(fileName)
    split_data = split_training_testing(0.7, data)

    clf = SVC(gamma='auto')
    return fit_and_predict(clf, split_data)

def IFOREST(fileName):
    print("Running Isolation Forest...")
    data = load_file(fileName)
    split_data = split_training_testing(0.7, data)

    clf = IsolationForest(contamination="auto" , behaviour="new")
    return fit_and_predict(clf, split_data)

def fit_and_predict(clf, split_data):
    clf.fit(split_data["training_features"], split_data["training_tags"])

    predicted = clf.predict(split_data["testing_features"])

    correct = 0
    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0
    total = 0
    for actualElem, predictedElem in zip(split_data["testing_tags"], predicted):
        if predictedElem > 0.5 and actualElem == 1:
            correct += 1
            true_positives += 1
        elif predictedElem < 0.5 and actualElem == 0:
            correct += 1
            true_negatives += 1
        elif predictedElem > 0.5 and actualElem == 0:
            false_positives += 1
        elif predictedElem < 0.5 and actualElem == 1:
            false_negatives += 1
        total += 1

    percentCorrect = correct / total
    print(f"False Positives: {false_positives}\nFalse Negatives: {false_negatives}")
    print(f"{correct} correct / {total} total = {percentCorrect * 100}%")

    zipped = zip(split_data["testing_tags"], predicted)
    dframe = pd.DataFrame(data=zipped)
    dframe.to_csv("../test.csv")

    return percentCorrect

def load_file(fileName):
    data = pd.read_csv(f"../data/{fileName}.csv")
    return data

def calculate_ratios(split_data):
    print("Calculating ratios of training and testing malicious vs benign...")
    count = 0
    for i in split_data["training_tags"]:
        if i == 1:
            count += 1
    ratio = count / len(split_data["training_tags"])
    print(f"Ratio training: {count} / {len(split_data['training_tags'])} = {ratio}")

    count = 0
    for i in split_data["testing_tags"]:
        if i == 1:
            count += 1
    ratio = count / len(split_data["testing_tags"])
    print(f"Ratio testing: {count} / {len(split_data['testing_tags'])} = {ratio}")

svm_pct = SVM("full_data_features")
gbt_pct = GBT("full_data_features")
rf_pct = RF("full_data_features")
i_forest = IFOREST("full_data_features")

print(f"\n\nOverview:"
      f"\nSVM: {svm_pct}"
      f"\nGBT: {gbt_pct}"
      f"\nRF: {rf_pct}"
      f"\nIForest: {i_forest}")