#!/usr/bin/env python

import json
import os
import signal
import subprocess
import time

import psutil

from fastbot import fastbot, launch_nox
import re
from androguard.misc import AnalyzeAPK


def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()

def dynamic_test(apk_path,pkg_name,json_output):
    apk_name=os.path.basename(apk_path)
    proxy=subprocess.Popen(
        f"mitmdump -s ./httpdump.py --set pkg_name={pkg_name} --set apk_name={apk_name}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    flag=fastbot(apk_path,pkg_name,4,"")
    time.sleep(20)
    # proxy.terminate()
    kill(proxy.pid)
    simple_path=f"./result_huawei/{pkg_name}-{apk_name}-simple.txt"
    if os.path.exists(simple_path):
        f = open(simple_path, "r", encoding="utf-8")
        simple = f.readlines()
        f.close()
        res_json = []
        for i in simple:
            res_json.append(json.loads(i))
        f = open(json_output, "w", encoding="utf-8")
        json.dump(res_json, f)
        f.close()
    return flag


def get_pkg_name(parm_apk_path):
    get_info_command = r"D:\ProgramFiles\Nox\bin\aapt dump badging %s" % (parm_apk_path)
    proc = subprocess.run(get_info_command,shell=True,stdout=subprocess.PIPE,text=True,errors="ignore")
    output=proc.stdout
    match = re.compile("package: name='(\S+)' versionCode='(\d+)' versionName='(\S+)'").match(output) #通过正则匹配，获取包名，版本号，版本名称
    if not match:
        raise Exception("can't get packageinfo")
    packagename = match.group(1)
    return packagename

def scale_run(apk_dir,output_dir):
    error=[]
    count=0
    for apk_name in os.listdir(apk_dir):
        apk_path=os.path.join(apk_dir,apk_name)
        try:
            pkg_name = get_pkg_name(apk_path)
            output = os.path.join(output_dir, apk_name + "_" + pkg_name)
            if os.path.exists(output):
                print(output," has been analysed!!!")
                continue
            os.mkdir(output)
            flag=dynamic_test(apk_path, pkg_name, os.path.join(output, "simple.json"))
            count+=1
            # if count%10==0:
            #     launch_nox()
            if not flag:
                error.append(apk_name)
            time.sleep(5)
        except:
            error.append(apk_name)
            continue

    return error



if __name__=="__main__":

    apk_root=''
    output=''
    scale_run(apk_root,output)


