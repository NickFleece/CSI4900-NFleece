import pandas as pd
from sklearn.svm import SVC
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import RandomForestClassifier
import pickle

def split_training_testing(ratio_training, data, onlyFeatures=True):
    print("Splitting data into training & test pairs...")
    splitFeatures = {
        "training_tags":[],
        "training_features":[],
        "testing_tags":[],
        "testing_features":[]
    }
    splitData = {
        "training":[],
        "testing":[]
    }

    num_training_elems = round(len(data) * ratio_training)
    for index,elem in data.iterrows():

        dataRow, row =  get_packet_features(elem, onlyFeatures)

        if len(splitFeatures["training_tags"]) >= num_training_elems:
            splitFeatures["testing_features"].append(row["features"])
            splitFeatures["testing_tags"].append(row["tag"])
            splitData["testing"].append(dataRow)
        else:
            splitFeatures["training_features"].append(row["features"])
            splitFeatures["training_tags"].append(row["tag"])
            splitData["training"].append(dataRow)

    calculate_ratios(splitFeatures)

    print("Splitting done!")
    return splitFeatures, splitData

def get_packet_features(elem, onlyFeatures=True):
    dataRow = []
    for _, i in elem.iteritems():
        dataRow.append(i)

    row = {
        "tag": None,
        "features": []
    }

    for tag, i in elem.iteritems():
        if tag == 'malicious':
            row["tag"] = i
        elif tag[:2] == "f_" or not onlyFeatures:
            row["features"].append(i)

    return dataRow, row

def GBT(fileName):
    print("Running GBT...")
    data = load_file(fileName)

    clf = GradientBoostingClassifier()
    return fit_and_predict(clf, data, "GBT")

def RF(fileName):
    print("Running Random Forest...")
    data = load_file(fileName)

    clf = RandomForestClassifier(n_estimators=100)
    return fit_and_predict(clf, data, "RF")

def SVM(fileName):
    print("Running SVM...")
    data = load_file(fileName)

    clf = SVC(gamma='auto')
    return fit_and_predict(clf, data, "SVM")

def fit_and_predict(clf, data, type):
    split_features, split_data = split_training_testing(0.7, data)
    feature_tags = []
    for i in data:
        feature_tags.append(i)

    print("Fitting...")
    clf.fit(split_features["training_features"], split_features["training_tags"])

    print("Predicting...")
    predicted = []
    if type == "GBT":
        predicted = clf.predict(split_features["testing_features"])
        confidence = predicted
    elif type == "SVM":
        predicted = clf.predict(split_features["testing_features"])
        print("Calculating confidence score...")
        confidence = clf.decision_function(split_features["testing_features"])
    elif type == "RF":
        predicted = clf.predict(split_features["testing_features"])
        print("Calculating confidence score...")
        confidence = clf.predict_proba(split_features["testing_features"])

    correct = 0
    total = 0
    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0
    results = []
    for dataFeatures, actualElem, predictedElem, confidenceScore in zip(split_data["testing"], split_features["testing_tags"], predicted, confidence):
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

        featureDict = {
            "actualTag": actualElem,
            "predictedTag": predictedElem,
            "confidenceScore": confidenceScore
        }
        for tag, feature in zip(feature_tags, dataFeatures):
            if tag not in ["Unnamed:0", "Unnamed:0.1", "malicious"]:
                featureDict[tag] = feature
        results.append(featureDict)

    df = pd.DataFrame(results)
    df.to_csv(f"../model_results/{type}.csv")

    result = {
        "accuracy": correct / total,
        "precision": true_positives / (true_positives + false_positives),
        "recall": true_positives / (true_positives + false_negatives)
    }
    print(f"False Positives: {false_positives}\nFalse Negatives: {false_negatives}")
    print(f"{correct} correct / {total} total = {result['accuracy'] * 100}%")

    return result, clf

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

def load_models():
    models = {
        "svm": None,
        "gbt": None,
        "rf": None
    }
    for i in models.keys():
        with open(f"../models/{i}", 'rb') as pickle_file:
            models[i] = pickle.load(pickle_file)
    return models

def predict_packet(pkt):
    models = load_models()
    data, row = get_packet_features(pkt)
    features = []
    for f in row['features']:
        features.append(f.tolist()[0])
    results = {}
    for model in models.keys():
        results[model] = models[model].predict([features])
    return results

def run_ML_train():
    svm_result, svm_clf = SVM("full_data_features")
    gbt_result, gbt_clf = GBT("full_data_features")
    rf_result, rf_clf = RF("full_data_features")

    print(f"\n\nOverview:"
          f"\nSVM: {svm_result['accuracy']}"
          f"\nGBT: {gbt_result['accuracy']}"
          f"\nRF: {rf_result['accuracy']}")

    scores = {
        "Model": ["SVM", "GBT", "RF"],
        "Accuracy": [svm_result["accuracy"], gbt_result["accuracy"], rf_result["accuracy"]],
        "Precision": [svm_result["precision"], gbt_result["precision"], rf_result["precision"]],
        "Recall": [svm_result["recall"], gbt_result["recall"], rf_result["recall"]],
        "F-Score": []
    }
    for type in [svm_result, gbt_result, rf_result]:
        f_score = 2 * ((type["precision"] * type["recall"]) / (type["precision"] + type["recall"]))
        scores["F-Score"].append(f_score)
    scores_df = pd.DataFrame(scores)
    scores_df.to_csv("../model_results/total_scores.csv")

    with open("../models/svm", 'wb') as file:
        pickle.dump(svm_clf, file)
    with open("../models/gbt", 'wb') as file:
        pickle.dump(gbt_clf, file)
    with open("../models/rf", 'wb') as file:
        pickle.dump(rf_clf, file)

# run_ML_train()