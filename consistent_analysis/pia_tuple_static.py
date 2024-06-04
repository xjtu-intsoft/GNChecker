#!/usr/bin/env python
# _*_ coding: utf-8 _*_

import json
import os
import re
from urllib.parse import urlparse

import IPy

def get_top_ip_name(target_ip):
    try:
        parsed_url = urlparse(target_ip)
        host_name = parsed_url.hostname
        return host_name.split('.')[-2]
    except:
        return None
def read_json(json_path):
    f=open(json_path,'r',encoding='utf-8')
    content=json.load(f)
    f.close()
    return content

def write_json(json_path,content):
    f=open(json_path,'w',encoding='utf-8')
    json.dump(content,f,ensure_ascii=False)
    f.close()

def getInfoType():
    info_map={"phone":{"getNetworkOperator":["mcc","mnc"],
                       "getDeviceId":["imei"],
                       "getSubscriberId":["imsi"],
                       "getLine1Number": ["phone_number"],
                       "getNetworkType": ["network"],
                       "getType":["network"],
                       "getSimOperator": ["mcc","mnc"],
                       "getSimSerialNumber": ["iccid"],
                       },
              "activity":{
                  "getRunningAppProcesses":["正在运行的应用进程"],
                  "getRunningServices":["正在运行的服务"],
                  "getRunningTasks":["正在运行的任务"],
                  "getRecentTasks":["最近运行的任务"]
              },
    }
    return info_map


def get_sys_info(taint_flow, info_map):
    if "wifi" in taint_flow[0] or "connectivity" in taint_flow[0]:
        return ["network"]
    else:
        for key in info_map.keys():
            if key in taint_flow[0]:
                for key_info in info_map[key].keys():
                    if key_info in str(taint_flow):
                        return info_map[key][key_info]
    return None


def get_pkg_name(taint_flow):
    package=taint_flow[-1].split(",")[3]
    if package.startswith("com"):
        return package.split(".")[1]
    return ""

def is_ip(address):
    try:
        IPy.IP(address)
        return True
    except Exception as e:
        return False

def one_app(json_path,info_map):
    flow_hash=set()
    info_hash=set()
    res=[]
    with open(json_path,"r",encoding="utf-8") as f:
        content=json.load(f)
        for item in content["net_trans"]:
            taint_flow=item["taint_flow"]
            #python 列表hash
            hash_value=hash(str(taint_flow))
            if hash_value not in flow_hash:
                flow_hash.add(hash_value)
                info_type=[]
                if item["data"]=="系统服务":
                    info_type=get_sys_info(taint_flow,info_map)
                    if info_type==None:
                        continue
                else:
                    info_type.append(item["data"])
                package_name=get_pkg_name(taint_flow)
                host=set()
                if len(item["target"])>0:
                    for ip in item["target"]:
                        if is_ip(ip):
                            host.add(ip)
                            continue
                        host_name=get_top_ip_name(ip)
                        host.add(host_name)
                triplet={"package_name": package_name, "info_type": info_type, "ip": list(host)}
                triplet_hash=hash(str(triplet))
                if triplet_hash not in info_hash:
                    info_hash.add(triplet_hash)
                    res.append(triplet)
    return res

def total_sta(root):
    info_map=getInfoType()
    for apk in os.listdir(root):
        try:
            package_name = os.listdir(os.path.join(root, apk))[0]
            data_sharing_path = os.path.join(root, apk, package_name, "data_sharing.json")
            if os.path.exists(data_sharing_path):
                print(data_sharing_path)
                triplet = one_app(data_sharing_path, info_map)
                write_json(os.path.join(root, apk, package_name, "triplet_static.json"), triplet)
        except:
            continue

if __name__=="__main__":
    static_result=''
    total_sta(static_result)


