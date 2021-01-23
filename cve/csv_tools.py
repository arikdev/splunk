class CSV_FILE:
    def __init__(self, file_name):
        self.file_name = file_name

    def implementation(self, tokens):
        print("No implemantation !!!!!")

    def process(self):
        with open(self.file_name, 'r') as fp:
            first = True
            for line in fp:
                if first:  # If the header of the csv
                    first = False
                    continue
                line = line[:-1]
                tokens = line.split(',')
                self.implementation(tokens)

    def to_dic(self):
        csv = []
        names = []
        with open(self.file_name, 'r') as fp:
            first = True
            for line in fp:
                line = line[:-1]
                tokens = line.split(',')
                if first:
                    first = False
                    for token in tokens:
                        names.append(token);
                    continue
                if len(tokens) < len(names):
                    print("Not enough tokens Line:" + line)
                    continue
                info = {}
                for ind, item in enumerate(names):
                    info[item] = tokens[ind]
                csv.append(info)
    
        return csv

