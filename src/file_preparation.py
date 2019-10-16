import csv
import random

def shuffle_combine_files(file1Data, file2Data):
    file1headers = file1Data.pop(0)
    file2headers = file2Data.pop(0)
    if file1headers != file2headers:
        print("The headers should be the same!")
    else:
        joinedFileData = file1Data + file2Data
        random.shuffle(joinedFileData)
        joinedFileData = [file1headers] + joinedFileData
        with open(f"../../Files/joined_data.csv", 'w', newline='') as writeFile:
            writer = csv.writer(writeFile)
            writer.writerows(joinedFileData)
    return None

def load_file(fileName):
    fileRows = []
    with open(f"../../Files/{fileName}.csv") as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            fileRows.append(row)
    return fileRows

def clean_file(fileName):
    temp_data = []
    count = 0
    new_id = 1
    with open(f"../../Files/{fileName}.csv") as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            count += 1
            if (count % 10000 == 0):
                print(count)
            if (row[4] == 'DNS' and row[7] == 'Message is a query' ):
                row[0] = new_id
                temp_data.append(row)
                new_id += 1
    with open(f"../../Files/cleaned_{fileName}.csv", 'w', newline='') as writeFile:
        writer = csv.writer(writeFile)
        writer.writerows(temp_data)
    return False

def main():
    selectedOption = input("Please enter one of these options:\n- 0: Clean data\n- 1: Combine and shuffle files\n")
    if selectedOption == '0':
        clean_file("packets2")
    elif selectedOption == '1':
        # file1 = input("File 1:")
        # file2 = input("File 2:")
        file1 = "cleaned_malicious"
        file2 = "cleaned_benign"
        file1_data = load_file(file1)
        file2_data = load_file(file2)
        shuffle_combine_files(file1_data, file2_data)
    else:
        return None
    return None

main()