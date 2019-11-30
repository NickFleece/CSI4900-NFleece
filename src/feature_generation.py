import math
import pandas as pd
import tldextract

def generate_features(
        csv_file_name,
        subdomain_length = True,
        number_subdomains = True,
        entropy = True,
        upper_ratio = True,
        lower_ratio = True,
        number_ratio = True
    ):

    data = pd.read_csv(f"../data/{csv_file_name}.csv")
    for i, row in data.iterrows():
        if i % 10000 == 0:
            print(f"Parsed {i} rows...")

        if subdomain_length:
            subdomain_length_val = calculate_length_of_subdomain(row['questionName'])
            data.set_value(i, 'f_subdomain_length', subdomain_length_val)

        if entropy:
            entropy_val = calculate_entropy(row['questionName'])
            data.set_value(i, 'f_subdomain_entropy', entropy_val)

        if number_subdomains:
            number_subdomains_val = calculate_number_subdomains(row['questionName'])
            data.set_value(i, 'f_number_subdomains', number_subdomains_val)

        if upper_ratio:
            upper_ratio_val = calculate_ratio_case_letters(row['questionName'], True)
            data.set_value(i, 'f_ratio_upper_case', upper_ratio_val)

        if lower_ratio:
            lower_ratio_val = calculate_ratio_case_letters(row['questionName'], False)
            data.set_value(i, 'f_ratio_lower_case', lower_ratio_val)

        if number_ratio:
            number_ratio_val = calculate_ratio_numbers(row['questionName'])
            data.set_value(i, 'f_ratio_numbers', number_ratio_val)

    data.to_csv(f"../data/{csv_file_name}_features.csv")

    return True

def calculate_length_of_subdomain(url):
    subdomain = get_subdomains(url)
    return len(subdomain)

def calculate_entropy(url):
    subdomain = get_subdomains(url)

    # get probability of chars in string
    prob = [float(url.count(c)) / len(url) for c in dict.fromkeys(list(url))]
    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy

def calculate_number_subdomains(url):
    subdomain = get_subdomains(url)
    splitSubdomains = subdomain.split('.')
    return len(splitSubdomains) - 1

def calculate_ratio_case_letters(url, isUpper):
    if isUpper:
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    else:
        letters = "abcdefghijklmnopqrstuvwxyz"

    subdomain = get_subdomains(url)

    totalCount = 0
    letterCount = 0
    for char in subdomain:
        if char in letters:
            letterCount += 1
        totalCount += 1

    if totalCount == 0:
        totalCount = 1

    return letterCount / totalCount

def calculate_ratio_numbers(url):
    numbers = "0123456789"

    subdomain = get_subdomains(url)

    totalCount = 0
    numberCount = 0
    for char in subdomain:
        if char in numbers:
            numberCount += 1
        totalCount += 1

    if totalCount == 0:
        totalCount = 1

    return numberCount / totalCount

#methods used by the feature generation


def get_subdomains(url):
    url = url[2:-2] #remove trailing comma left over from preprocessing
    #get rid of suffix
    suffix = tldextract.extract(url).suffix
    if suffix != '':
        newurl = url[:-(len(suffix) + 1)]
    else:
        #tldextract couldn't figure out what to do with this
        if url[-8:-4] == 'a123': #our malicious data
            newurl = url[:-4]
        elif url[-4:] in ['.lan', '.ide']:
            newurl = url[:-4]
        else:
            # print(f"Not sure how to get the subdomain of: {url}")
            return url

    #remove the www at the beginning
    if newurl[0:4] == 'www.':
        newurl = newurl[4:]

    return newurl

def clean_feature_dataset(file):
    df = pd.read_csv(f"../data/{file}.csv")
    clean = []
    for i, row in df.iterrows():
        try:
            float(row['f_subdomain_length'])
            float(row['f_number_subdomains'])
            float(row['f_subdomain_entropy'])
            float(row['f_ratio_upper_case'])
            float(row['f_ratio_lower_case'])
            float(row['f_ratio_numbers'])
        except Exception as e:
            print(f"Something went wrong with packet {i}: {e}")

        # subdomain_length = True,
        # number_subdomains = True,
        # entropy = True,
        # upper_ratio = True,
        # lower_ratio = True,
        # number_ratio = True

#main
glblCount = 0
generate_features("full_data")
# clean_feature_dataset("full_data_features")