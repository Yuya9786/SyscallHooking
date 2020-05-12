#!/bin/sh
# 検出対象ログファイル
TARGET_LOG="/var/log/messages"

# 検出文字列
_error_conditions="syscall:[unlink]"

# ログファイルを監視する関数
hit_action() {
    while read i
    do
        echo $i | grep -q "${_error_conditions}"
        if [ $? = "0" ];then
            # アクション
            echo $i
        fi
    done
}

# main
if [ ! -f ${TARGET_LOG} ]; then
    touch ${TARGET_LOG}
fi

tail -n 0 --follow=name --retry $TARGET_LOG | hit_actionvi