import csv

def load_dataset(fileName):
    return None

def clean_file(fileName):
    temp_data = []
    count = 0
    new_id = 1
    with open(f"../../Datasets/{fileName}.csv") as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        for row in readCSV:
            count += 1
            if (row[4] == 'DNS' and row[7] == 'Message is a query' ):
                if (count % 10000 == 0):
                    print(count)
                row[0] = new_id
                temp_data.append(row)
                new_id += 1
    with open(f"cleaned_{fileName}.csv", 'w', newline='') as writeFile:
        writer = csv.writer(writeFile)
        writer.writerows(temp_data)
    return False

def main():
    # selectedOption = input("Please enter one of these options:\n- 0: Clean data\n")
    file_cleaned = clean_file("20160423_data")
    return None

main()