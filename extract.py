import re
def extract_functions(file):

    namelist = []
    with open(file,'r') as f:
        while True:
            line = f.readline()
            if line == "":
                break
            if line[0:9] == "  (func $":
                start = 9
                end = 10
                while line[end] != ' ':
                    end += 1
                name = line[start:end]
                namelist.append(name)
    f.close()

    print(namelist)


extract_functions("dnet.wat")