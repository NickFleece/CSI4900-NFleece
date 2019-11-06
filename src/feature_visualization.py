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

    plt.scatter(x, y, c=color, s=1)
    plt.title(featureName)
    plt.show()

data = pd.read_csv("../data/full_data_features.csv")
# graph_feature(data, 'f_subdomain_entropy')
# graph_feature(data, 'f_ratio_upper_case')
# graph_feature(data, 'f_ratio_numbers')
# graph_feature(data, 'f_subdomain_length')
# graph_feature(data, 'f_ratio_lower_case')
# graph_feature(data, 'f_number_subdomains')