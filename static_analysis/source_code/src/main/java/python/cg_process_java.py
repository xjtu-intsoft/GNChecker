#!/usr/bin/env python
# _*_ coding: utf-8 _*_
# @Time : 2023/7/9 15:52
# @Author : xxx
# @Version：V 0.1
# @File : cg_process_java.py
# @desc :
#!/usr/bin/env python
# _*_ coding: utf-8 _*_
# @Time : 2023/6/27 10:52
# @Author : xxx
# @Version：V 0.1
# @File : cg_process.py
# @desc :
import json
import sys
import networkx as nx
from pymongo import MongoClient
import matplotlib.pyplot as plt

def cg_deleted_integration(api_used_json,scenes_json,package_name):
    f = open(api_used_json, "r", encoding="utf-8")
    api_used = json.load(f)
    f.close()
    f = open(scenes_json, "r", encoding="utf-8")
    scenes = json.load(f)
    f.close()
    api_map={}
    nodes_num_map={}
    cg={"nodes":{},"edges":{}}
    id=0
    edge_id=0
    for i in api_used.keys():
        used=api_used[i]["used"]
        api_map[i]=[]
        for j in used:
            # api_map[i].append(j["invoke_chain"])
            for z in range(len(j["invoke_chain"])):
                node=j["invoke_chain"][z]
                if node not in cg["nodes"].keys():
                    cg["nodes"][node]={}
                    cg["nodes"][node]["id"]=package_name+"_"+str(id)
                    id+=1
                if node in nodes_num_map.keys():
                    nodes_num_map[node]+=1
                else:
                    nodes_num_map[node]=1
            for z in range(len(j["invoke_chain"])):
                if z+1<len(j["invoke_chain"]):
                    parent = j["invoke_chain"][z]
                    child=j["invoke_chain"][z+1]
                    parent_id=cg["nodes"][parent]["id"]
                    child_id=cg["nodes"][child]["id"]

                    edge_key=parent_id+child_id
                    if edge_key in cg['edges'].keys():
                        cg['edges'][edge_key]["call_sum"]+=1
                    else:
                        tmp=package_name + "_" + str(edge_id)
                        cg["edges"][edge_key]={"info":{},"call_sum":0}
                        cg["edges"][edge_key]["info"]={"source":parent_id,"target":child_id,"id":tmp}
                        cg['edges'][edge_key]["call_sum"] = 1
                        api_map[i].append(tmp)
                        edge_id+=1
    for i in scenes.keys():
        for j in scenes[i]:
            api=j["invoke_chain"][-1]
            if api not in api_map.keys():
                api_map[api]=[]
            # api_map[api].append(j["invoke_chain"])
            for z in range(len(j["invoke_chain"])):
                node = j["invoke_chain"][z]
                if node not in cg["nodes"].keys():
                    cg["nodes"][node] = {}
                    cg["nodes"][node]["id"] = package_name+"_"+str(id)
                    id+=1
                if node in nodes_num_map.keys():
                    nodes_num_map[node] += 1
                else:
                    nodes_num_map[node] = 1
            for z in range(len(j["invoke_chain"])):
                if z + 1 < len(j["invoke_chain"]):
                    parent = j["invoke_chain"][z]
                    child = j["invoke_chain"][z + 1]
                    parent_id = cg["nodes"][parent]["id"]
                    child_id = cg["nodes"][child]["id"]
                    edge_key = parent_id + child_id
                    if edge_key in cg['edges'].keys():
                        cg['edges'][edge_key]["call_sum"] += 1
                    else:
                        tmp = package_name + "_" + str(edge_id)
                        cg["edges"][edge_key] = {"info": {}, "call_sum": 0}
                        cg["edges"][edge_key]["info"] = {"source": parent_id, "target": child_id, "id": tmp}
                        cg['edges'][edge_key]["call_sum"] = 1
                        api_map[api].append(tmp)
                        edge_id += 1
    for i in cg["nodes"].keys():
        cg["nodes"][i]["num"]=nodes_num_map[i]

    return cg,api_map

def insertToMongodb(api_used_json,scenes_json,apk_name,package_name):
    client = MongoClient('202.117.43.248', 27071)
    db = client["cert"]
    cg_table = db["control_flow"]
    node_table = db["nodes_map"]
    api_table=db["api_map"]
    cg, api_map = cg_deleted_integration(api_used_json,scenes_json,package_name)
    nodes_data=[]
    for i in cg["nodes"].keys():
        nodes_data.append({"package_name":package_name,"name":i,"id": cg["nodes"][i]["id"],"in_degree":cg["nodes"][i]["num"]})
    lama=50
    mod=len(nodes_data) % lama
    if mod==0:
        count=len(nodes_data)/lama
    else:
        count=(len(nodes_data)-mod)/lama+1
    count=int(count)
    for i in range(count-1):
        node_table.insert_many(nodes_data[i*lama:(i+1)*lama])
    node_table.insert_many(nodes_data[(count-1) * lama:])

    api_data=[]
    for i in api_map.keys():
        api_data.append({"apk_name": apk_name, "package_name": package_name, "api":i,"cg": api_map[i]})

    mod1=len(api_data) % lama
    if mod==0:
        count=len(api_data)/lama
    else:
        count=(len(api_data)-mod1)/lama+1
    count = int(count)
    for i in range(count-1):
        api_table.insert_many(api_data[i*lama:(i+1)*lama])
    api_table.insert_many(api_data[(count-1) * lama:])


    edge_data=[]
    for i in cg["edges"].keys():
        edge_data.append({"package_name":package_name,"id": cg["edges"][i]["info"]["id"],"source":cg["edges"][i]["info"]["source"],"target":cg["edges"][i]["info"]["target"],"call_sum":cg["edges"][i]["call_sum"]})
    mod3=len(edge_data) % lama
    if mod==0:
        count=len(edge_data)/lama
    else:
        count=(len(edge_data)-mod3)/lama+1
    count = int(count)
    for i in range(count-1):
        cg_table.insert_many(edge_data[i*lama:(i+1)*lama])
    cg_table.insert_many(edge_data[(count-1) * lama:])


# cg,api_map=cg_deleted_integration(r"D:\cert\应用示例\apk\1\百度地图\sensi_api_used.json",
#                      r"D:\cert\应用示例\apk\1\百度地图\SensitiveScenes.json","com.baidu.BaiduMap")
# print(cg)

# insertToMongodb(r"D:\cert\应用示例\apk\1\百度地图\sensi_api_used.json",
#                      r"D:\cert\应用示例\apk\1\百度地图\SensitiveScenes.json","百度地图.apk","com.baidu.BaiduMap")


def cg_netx_generate(api_used,sensitive_scenes):
    f = open(api_used, "r", encoding="utf-8")
    api_used = json.load(f)
    f.close()
    f = open(sensitive_scenes, "r", encoding="utf-8")
    scenes = json.load(f)
    f.close()
    sinks=set()
    sources=set()
    cg = {"nodes": {}, "edges": {}}
    id = 0
    edge_id = 0
    for i in api_used.keys():
        used = api_used[i]["used"]
        sources.add(i)
        for j in used:
            # api_map[i].append(j["invoke_chain"])
            for z in range(len(j["invoke_chain"])):
                node = j["invoke_chain"][z]
                if node not in cg["nodes"].keys():
                    cg["nodes"][node] = id
                    id += 1
            for z in range(len(j["invoke_chain"])):
                if z + 1 < len(j["invoke_chain"]):
                    parent = j["invoke_chain"][z]
                    child = j["invoke_chain"][z + 1]
                    parent_id = cg["nodes"][parent]
                    child_id = cg["nodes"][child]

                    edge_key = str(parent_id) +"_"+ str(child_id)
                    if edge_key in cg['edges'].keys():
                        cg['edges'][edge_key]["call_sum"] += 1
                    else:
                        tmp = edge_id
                        cg["edges"][edge_key] = {"info": {}, "call_sum": 0}
                        cg["edges"][edge_key]["info"] = {"source": child_id, "target": parent_id, "id": tmp}
                        cg['edges'][edge_key]["call_sum"] = 1
                        edge_id += 1
    for i in scenes.keys():
        for j in scenes[i]:
            sinks.add(j["invoke_chain"][-1])
            # api_map[api].append(j["invoke_chain"])
            for z in range(len(j["invoke_chain"])):
                node = j["invoke_chain"][z]
                if node not in cg["nodes"].keys():
                    cg["nodes"][node] =id
                    id += 1
            for z in range(len(j["invoke_chain"])):
                if z + 1 < len(j["invoke_chain"]):
                    parent = j["invoke_chain"][z]
                    child = j["invoke_chain"][z + 1]
                    parent_id = cg["nodes"][parent]
                    child_id = cg["nodes"][child]
                    edge_key = str(parent_id) +"_"+ str(child_id)
                    if edge_key in cg['edges'].keys():
                        cg['edges'][edge_key]["call_sum"] += 1
                    else:
                        tmp = edge_id
                        cg["edges"][edge_key] = {"info": {}, "call_sum": 0}
                        cg["edges"][edge_key]["info"] = {"source": parent_id, "target": child_id, "id": tmp}
                        cg['edges'][edge_key]["call_sum"] = 1
                        edge_id += 1
    G=nx.DiGraph()
    nodes=[]
    edges=[]
    for i in cg["nodes"].keys():
        nodes.append(cg["nodes"][i])
    for i in cg["edges"].keys():
        o_edge=cg["edges"][i]
        t_edge=(o_edge["info"]["source"],o_edge["info"]["target"],o_edge["call_sum"])
        edges.append(t_edge)
    G.add_nodes_from(nodes)
    G.add_weighted_edges_from(edges)
    #可视化
    # pos=nx.circular_layout(G)
    # nx.draw(G,pos,with_labels=True,font_weight="bold")
    # plt.xticks([])
    # plt.yticks([])
    # plt.title('AOE_CPM', fontsize=10)
    # plt.show()

    return cg,G,sinks,sources
def find_pathes(api_used,sensitive_scenes):
    cg,G,sinks,sources=cg_netx_generate(api_used,sensitive_scenes)
    sinks_id=[]
    sources_id=[]
    for i in sinks:
        sinks_id.append(cg["nodes"][i])
    for i in sources:
        try:
            sources_id.append(cg["nodes"][i])
        except:
            continue
    source_to_sink=[]
    node_retravers={}
    for i in cg["nodes"].keys():
        node_retravers[cg["nodes"][i]]=i
    for i in sources_id:
        for j in sinks_id:
            pathes=list(nx.all_simple_paths(G,i,j))
            if len(pathes)>0:
                pathes_with_sig=[]
                for n in pathes:
                    one_path=[]
                    for m in n:
                        one_path.append(node_retravers[m])
                    pathes_with_sig.append(one_path)
                source_to_sink.append({"source": node_retravers[i], "target": node_retravers[j], "pathes": pathes_with_sig})
    return source_to_sink


def getClass(sig):
    "".split()
    return sig.split(":")[0][1:]

def length(e):
    return len(e)

def getClasses(source_to_sink,class_path):
    classes=[]
    methods=set()
    for i in source_to_sink:
        pathes=i["pathes"]
        for j in pathes:
            clazz_one_time = set()
            for sig in j:
                methods.add(sig)
                clazz=getClass(sig)
                clazz_one_time.add(clazz)
            classes.append(list(clazz_one_time))
    content=[]
    for i in classes:
        content.append(i)

    list_len = []
    list.sort(content, key=length)
    for i in range(len(content)):
        b = False
        for j in range(i + 1, len(content)):
            if set(content[i]).issubset(content[j]):
                b = True
        if not b:
            list_len.append(content[i])
    f=open(class_path,"w",encoding="utf-8")
    json.dump(list_len,f)
    f.close()
    return list_len
def main(api_used,sensitive_scenes,output):
    source_to_sink = find_pathes(api_used,sensitive_scenes)
    getClasses(source_to_sink, output)

if __name__ == '__main__':
    api_used=str(sys.argv[1])
    sensitive_scenes=str(sys.argv[2])
    output=str(sys.argv[3])
    main(api_used,sensitive_scenes,output)



