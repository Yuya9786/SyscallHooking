import re

with open("define.txt") as f:
    l = f.readlines()
    for i in range(0, 325):
        a = re.findall('__NR_(.*) ', l[i])[0]
        b = "\telse if (num == __NR_"+ a +")\n\t\tsyscall_name = \"" + a +"\";"
        print(b)