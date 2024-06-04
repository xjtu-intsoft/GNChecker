#!/usr/bin/env python
# _*_ coding: utf-8 _*_

# @desc : 隐私政策gpt格式化结果与数据流分析一致性比对分析
import json
from urllib.parse import urlparse
from consistency.jaccard_similarity import JaccardSimilarity
import os

def read_json1(json_path):
    if not os.path.exists(json_path):
        return []
    f=open(json_path,'r',encoding='utf-8')
    content=json.load(f)
    f.close()
    return content
def read_json(json_path):
    f=open(json_path,'r',encoding='utf-8')
    content=json.load(f)
    f.close()
    return content

def write_json(json_path,content):
    f=open(json_path,'w',encoding='utf-8')
    json.dump(content,f,ensure_ascii=False)
    f.close()


def get_top_ip_name(target_ip):
    try:
        parsed_url = urlparse(target_ip)
        host_name = parsed_url.hostname
        return host_name.split('.')[-2]
    except:
        return None


def is_info_stated(info_map,real_info, pp_statement):
    res=[]
    is_stated=True
    for info in real_info:
        core_word=[]
        core_word.append(info)
        for m in info_map:
            if info.lower() in m["core_word"]:
                core_word.extend(m["core_word"])
                break
        info_stated=False
        for word in core_word:
            for pp_info in pp_statement["信息类型"]:
                similarity = JaccardSimilarity(word.lower(), pp_info.lower())
                similarity = similarity.main()
                if similarity>0.5:
                    info_stated=True
                    break
            if info_stated:
                break
        if not info_stated:
            res.append(info)
            is_stated=False
    return is_stated,res


def is_vague_statement(info_map, info, pp_statement):
    is_vague=False
    for i in info:
        parent_type=None
        for map in info_map:
            if "parent_type" in map.keys() and i.lower() in map["core_word"]:
                parent_type=map["parent_type"]
                break
        if not parent_type==None:
            for info_type in parent_type:
                for pp_info in pp_statement["信息类型"]:
                    similarity = JaccardSimilarity(info_type, pp_info)
                    similarity = similarity.main()
                    if similarity>0.5:
                        is_vague=True
                        break
                if is_vague:
                    break
    return is_vague


def one_app(info_map,triplet_static_json,triplet_dynamic_json,pp_json,party_info_path,out_path):
    res = {"no_statement": [], "vague_statement": []}
    party_info = read_json(party_info_path)
    triplet_static = read_json1(triplet_static_json)
    dynamic_static = read_json1(triplet_dynamic_json)
    for i in dynamic_static:
        if len(i["info_type"])>0:
            triplet_static.append(i)
    pp_data = read_json(pp_json)
    party_map = {}
    # 第三方字典构造
    for i in party_info:
        for j in i['ip']:
            if j not in party_map.keys():
                party_set = set()
                party_set.add(i['服务商'])
                for p in i['别名']:
                    party_set.add(p)
                party_map[j] = party_set
            else:
                party_map[j].add(i['服务商'])
                for p in i['别名']:
                    party_map[j].add(p)
    print(party_map)

    for info in triplet_static:
        packget_name=info['package_name']
        if packget_name=="":
            if len(info['ip'])>0:
                packget_name=info['ip'][0]
        if packget_name=="":
            continue

        pp_statement=None
        if packget_name in party_map.keys():
            third_party=party_map[packget_name]
            for party_name in third_party:
                for pp_party in pp_data["third_party"]:

                    try:
                        if party_name in pp_party['服务商']:
                            pp_statement=pp_party
                            break
                        similarity = JaccardSimilarity(party_name, pp_party['服务商'])
                        similarity = similarity.main()
                        if similarity > 0.5:
                            pp_statement = pp_party
                            break
                    except:
                        continue

        if pp_statement == None:
            res["no_statement"].append({ "data":info["info_type"], "third_party": packget_name})
        else:
            is_stated,last_info=is_info_stated(info_map,info["info_type"], pp_statement)
            if not is_stated:
                if is_vague_statement(info_map,last_info, pp_statement):
                    res["vague_statement"].append(
                        {"real_data": info["info_type"], "third_party": pp_statement["服务商"]+"_"+packget_name,"pp_statemet": pp_statement})
                else:
                    res["no_statement"].append(
                        {"real_data": info["info_type"], "third_party": pp_statement["服务商"]+"_"+packget_name,"pp_statemet": pp_statement})
        write_json(out_path, res)

def total_sta():
    # pp_root = r"D:\cert\实验\consistency\pp\predict"
    # static_root=r"D:\cert\实验\consistency\static_analyse"
    # dynamic_root=r"D:\cert\实验\consistency\dynamic_test"
    # party_info_path=r"E:\数据流论文\input\party_info1.json"
    # res_root=r"D:\cert\实验\consistency\result2"
    # info_map_json=r"E:\数据流论文\input\type-tse.json"

    pp_root = r"D:\cert\实验\consistency_huawei\predict"
    static_root = r"D:\cert\实验\consistency_huawei\static_analyse"
    dynamic_root = r"D:\cert\实验\consistency_huawei\dynamic_test"
    party_info_path = r"E:\数据流论文\input\party_info1.json"
    res_root = r"D:\cert\实验\consistency_huawei\result2"
    info_map_json = r"E:\数据流论文\input\type-tse.json"

    info_map=read_json(info_map_json)
    for package in os.listdir(pp_root):
        pp_json_path=os.path.join(pp_root,package,"third_party_info.json")
        apk_name=""
        for apk in os.listdir(static_root):
            try:
                if package == os.listdir(os.path.join(static_root, apk))[0]:
                    apk_name = apk
                    break
            except:
                pass
        if apk_name=="":
            for apk in os.listdir(dynamic_root):
                package_name=apk.split("_")[1]
                if package==package_name:
                    apk_name=apk.split("_")[0]
                    break
        if apk_name=="":
            print("no apk: ",apk_name)
            continue
        triplet_static_json=os.path.join(static_root,apk_name,package,"triplet_static.json")
        triplet_dynamic_json=os.path.join(dynamic_root,apk_name+"_"+package,"triplet_dynamic.json")
        outpout_dir=os.path.join(res_root,apk+"_"+package)
        if not os.path.exists(outpout_dir):
            os.mkdir(outpout_dir)
        one_app(info_map,triplet_static_json,triplet_dynamic_json,pp_json_path,party_info_path,os.path.join(outpout_dir,"no_consistent.json"))

def total_info_type():
    # pp_root = r"D:\cert\实验\consistency\pp\predict"
    # static_root=r"D:\cert\实验\consistency\static_analyse"
    # dynamic_root=r"D:\cert\实验\consistency\dynamic_test"
    # party_info_path=r"E:\数据流论文\input\party_info1.json"
    # res_root=r"D:\cert\实验\consistency\result2"
    # info_map_json=r"E:\数据流论文\input\type-tse.json"
    data=[]

    static_root = r"D:\cert\实验\consistency_huawei\static_analyse"
    dynamic_root = r"D:\cert\实验\consistency_huawei\dynamic_test"
    for i in os.listdir(dynamic_root):
        json_path=os.path.join(dynamic_root,i,"triplet_dynamic.json")
        if os.path.exists(json_path):
            content=read_json(json_path)
            for m in content:
                for info in m["info_type"]:
                    for info1 in info.split(" "):
                        data.append({"ip_name": m["package_name"], "info_type": info1.lower()})
    for i in os.listdir(static_root):
            json_path = os.path.join(static_root, i,os.listdir(os.path.join(static_root,i))[0],"triplet_static.json")
            if os.path.exists(json_path):
                content = read_json(json_path)
                for m in content:
                    for info in m["info_type"]:
                        for info1 in info.split(" "):
                            data.append({"ip_name": m["package_name"], "info_type": info1.lower()})


    static_root=r"D:\cert\实验\consistency\static_analyse"
    dynamic_root=r"D:\cert\实验\consistency\dynamic_test"
    for i in os.listdir(dynamic_root):
        json_path=os.path.join(dynamic_root,i,"triplet_dynamic.json")
        if os.path.exists(json_path):
            content=read_json(json_path)
            for m in content:
                for info in m["info_type"]:
                    for info1 in info.split(" "):
                        data.append({"ip_name": m["package_name"], "info_type": info1.lower()})
    for i in os.listdir(static_root):
            try:
                json_path = os.path.join(static_root, i, os.listdir(os.path.join(static_root, i))[0],
                                         "triplet_static.json")
                if os.path.exists(json_path):
                    content = read_json(json_path)
                    for m in content:
                        for info in m["info_type"]:
                            for info1 in info.split(" "):
                                data.append({"ip_name": m["package_name"], "info_type": info1.lower()})
            except:
                continue
    write_json(r"D:\cert\实验\consistency\total_heat_map.json",data)






if __name__=="__main__":
    # one_app(r'D:\cert\实验\anzhi_9\andr.album_andr.album_54087100.apk\data_sharing.json'
    #                     ,r'D:\cert\实验\dataset\predict\air.tv.douyu.android\third_party_info.json',
    #                     r'E:\数据流论文\input\party_info.json',
    #                     r"D:\cert\实验\anzhi_9\andr.album_andr.album_54087100.apk\no_consistent.json")
    # total_sta()
    total_info_type()







