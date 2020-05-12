import sys
import os



# 指定ファイルを読み込み
def get_log_from_file(file_name):

    # CP932のコードを?に
    log_file = open(file_name,'r',encoding='CP932', errors='replace')

    log = log_file.read()
    log_file.close()

    return log

if __name__ == '__main__':
    argv = sys.argv
    argc = len(argv)

    if argc != 2:
        print("usage: " + argv[1] + " [file]")
        quit()

    filename = argv[1]
    os.system('tail -f ' + filename )