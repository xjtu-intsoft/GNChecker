#!/usr/bin/env python
# _*_ coding: utf-8 _*_

import os
import shutil
import subprocess
import time
import signal
import threading
from concurrent.futures import ProcessPoolExecutor, TimeoutError,as_completed
def launch_nox():
    quit_command = "D:\\ProgramFiles\\Nox\\bin\\NoxConsole.exe quit -index:1"
    launch_command = "D:\\ProgramFiles\\Nox\\bin\\NoxConsole.exe launch -index:1"
    try:
        os.popen(quit_command)
    except Exception as ex:
        pass
    time.sleep(30)
    try:
        os.popen(launch_command)
    except Exception as ex:
        pass
    time.sleep(60*3)

def adb_apk_install(apk_path):
    command = r"D:\ProgramFiles\Nox\bin\adb install -r -d %s" % (apk_path)
    try:
        f = os.popen(command)
        output = f.readlines()
        if ("Success" not in output[-1]):
            if "Failed to install" in output[-1]:
                launch_nox()
                os.popen(command)
                if ("Success" not in output[-1]):
                    return False
                else:
                    return True
            if "- waiting for device -" in output[-1]:
                launch_nox()
                os.popen(command)
                if ("Success" not in output[-1]):
                    return False
                else:
                    return True
        else:
            return True
    except Exception as ex:
        return False

def adb_apk_uninstall(package_name):
    command = r"D:\ProgramFiles\Nox\bin\adb uninstall %s" % (package_name)
    try:
        f = os.popen(command)
        output = f.readlines()
        if ("Success" not in output[-1]):
            return False
        else:
            return True
    except Exception as ex:
        return False

def adb_pull(source_path, target_path):
    command = r"D:\ProgramFiles\Nox\bin\adb pull %s %s" % (source_path, target_path)
    try:
        f = os.popen(command)
        output = f.readlines()
        if ("Success" not in output[-1]):
            return False
        else:
            return True
    except Exception as ex:
        return False

def adb_delete(path):
    command = r"D:\ProgramFiles\Nox\bin\adb shell rm -r %s" % (path)
    try:
        p = subprocess.Popen(command, shell=True)
        p.wait()
        return True
    except Exception as ex:
        return False

def timeout_action():
    raise Exception("timeout")

def adb_apk_monkey(package_name,dynamic_time_limit,fastbot_result_path):

    command = r"D:\ProgramFiles\Nox\bin\adb  shell CLASSPATH=/sdcard/monkeyq.jar:/sdcard/framework.jar:" \
              "/sdcard/fastbot-thirdpart.jar exec app_process /system/bin " \
              "com.android.commands.monkey.Monkey -p %s --agent reuseq " \
              "--running-minutes %s --throttle 1500 -v -v" %(package_name,dynamic_time_limit)
    # fastbot_result_path=os.path.join(r'F:\Python_Workplace\GUItry\Fastbot_result',package_name)
    # if(os.path.exists(fastbot_result_path)):
    #     shutil.rmtree(fastbot_result_path)
    # os.mkdir(fastbot_result_path)
    # command+=";adb pull /sdcard/max1/ %s"%(fastbot_result_path)

    # try:
    #     p = subprocess.Popen(command, shell=True)
    #     # '*** ERROR *** WATCHDOG: Blocked in monitor'
    #     p.wait()
    #     # time.sleep(1.25*60)
    #     # adb_pull("/sdcard/max1/",fastbot_result_path)
    #     adb_delete("/sdcard/max1/")
    #     return True
    # except Exception as ex:
    #     return False

    try:
        p = subprocess.Popen(command, shell=True)
        # '*** ERROR *** WATCHDOG: Blocked in monitor'
        # time.sleep(1.25*60)
        # adb_pull("/sdcard/max1/",fastbot_result_path)
        time_out = 10*60
        p.wait(timeout=time_out)
        adb_delete("/sdcard/max1/")
        return True
    except TimeoutError:
        print("Task exceeded the timeout limit.")
        launch_nox()
        p.terminate()
        p.wait()
        return False
    except Exception as ex:
        print("Task exceeded the timeout limit.！！！")
        launch_nox()
        print(ex)
        p.terminate()
        p.wait()
        return False


def fastbot(apk_path,package_name,dynamic_time_limit,fastbot_result_path):
    try:
        adb_apk_install(apk_path)
        # try:
        flag = adb_apk_monkey(package_name, dynamic_time_limit, fastbot_result_path)
        # except timeout_decorator.TimeoutError:
        #     launch_nox()
        #     time.sleep(10)
        adb_apk_uninstall(package_name)
    except:
        return False
    return True


if __name__=="__main__":
    # fastbot(r"D:\cert\实验\consistency\consistency_apk\义渡热爱.apk","com.xhl.dadukou",1,"")
    launch_nox()