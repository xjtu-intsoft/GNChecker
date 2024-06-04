#!/usr/bin/env python
# _*_ coding: utf-8 _*_


import json
import os
import re
from urllib.parse import urlparse
import IPy

def read_json(json_path):
    f=open(json_path,'r',encoding='utf-8')
    content=json.load(f)
    f.close()
    return content

def write_json(json_path,content):
    f=open(json_path,'w',encoding='utf-8')
    json.dump(content,f,ensure_ascii=False)
    f.close()
def is_ip(address):
    try:
        IPy.IP(address)
        return True
    except Exception as e:
        return False


def get_top_ip_name(target_ip):
    try:
        parsed_url = urlparse(target_ip)
        host_name = parsed_url.hostname
        return host_name.split('.')[-2]
    except:
        return None
def get_host_name(target_ip):
    try:
        parsed_url = urlparse(target_ip)
        host_name = parsed_url.hostname
        return host_name
    except:
        return None

import re

def remove_non_alpha(s):
    # 使用正则表达式匹配所有非字母字符并替换为空字符串
    return re.sub(r'[^a-zA-Z]', '', s)
def get_word_type():

    info_type=read_json(r"info_type.json")
    res=[]
    for i in info_type:
        res.append(remove_non_alpha(i.lower()))
    return res

def get_words(str):
    words = re.findall(r'\w+', str)
    res=[]
    for word in words:
        if word.lower() in res:
            continue
        else:
            res.append(remove_non_alpha(word.lower()))
    return res

def one_app(simple_json,info_type):
    f=open(simple_json,"r",encoding="utf-8")
    content=json.load(f)
    f.close()
    res=[]
    info_hash=set()
    for flow in content:
        info = []
        url=flow["url"]
        hostname=get_host_name(url)
        if not is_ip(hostname):
            ip_name=get_top_ip_name(url)
            if ip_name=="bignox":
                continue
            content = eval(flow["content"])
            for key in content['query'].keys():
                info.append(remove_non_alpha(key.lower()))
            # info.extend(content['query'].keys())
            if isinstance(content['content'], dict):
                for key in content['content'].keys():
                    info.append(remove_non_alpha(key.lower()))
                # info.extend(content['content'].keys())
            else:
                words=get_words(content['content'])
                info.extend(words)
            info_type=set(info)&set(info_type)
            info_type=list(info_type)

            triplet = {"package_name": ip_name, "info_type": info_type}
            triplet_hash = hash(str(triplet))
            if triplet_hash not in info_hash:
                info_hash.add(triplet_hash)
                res.append(triplet)

    return res
def total_sta(root):
    info_type=get_word_type()
    for apk in os.listdir(root):
        simple_path=os.path.join(root,apk,"simple.json")
        if os.path.exists(simple_path):
            print(simple_path)
            triplet=one_app(simple_path,info_type)
            write_json(os.path.join(root,apk,"triplet_dynamic.json"),triplet)
if __name__ == '__main__':
    dynamic_result=''
    total_sta(dynamic_result)
