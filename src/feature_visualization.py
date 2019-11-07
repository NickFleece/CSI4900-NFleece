import pandas as pd
from matplotlib import pyplot as plt

def graph_feature(data, featureName):
    count = 0
    x = []
    y = []
    color = []
    for _, row in data.iterrows():
        x.append(count)
        y.append(row[featureName])
        color.append(row['malicious'])
        count += 1

    return [x,y,color]
    # plt.scatter(x, y, c=color, s=1)
    # plt.title(featureName)
    # plt.show()

data = pd.read_csv("../data/full_data_features.csv")
features = [
    'f_subdomain_entropy',
    'f_ratio_upper_case',
    'f_ratio_numbers',
    'f_subdomain_length',
    'f_ratio_lower_case',
    'f_number_subdomains'
]
x_max = 3
y_max = 2
fig, ax = plt.subplots(y_max, x_max)
for feat, i in zip(features, range(0,len(features))):
    print(f"Processing feature: {feat}, i: {i}, x: {i%x_max}, y: {i//(y_max+1)}")
    graph_data = graph_feature(data, feat)
    ax[(i//(y_max+1)), (i%x_max)].scatter(graph_data[0], graph_data[1], c=graph_data[2], s=1)
    ax[(i//(y_max+1)), (i%x_max)].set_title(feat)
plt.show()