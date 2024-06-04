#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import json
import os.path
import sys
import igraph as ig



def readJson(path):
    f=open(path,"r",encoding="utf-8")
    content=json.load(f)
    f.close()
    return content
def writeJson(object,path):
    f=open(path,"w",encoding="utf-8")
    json.dump(object,f,ensure_ascii=False)
    f.close()
    return None

def data_collect_filter3(data_collect_path,out_put_path):
    #根据生命周期函数及时间函数进行过滤
    res={}
    # event_key = ["onCreate","onClick","service","onResume","onStart","onPause","onStop","onRestart","onDestroy"]
    event_key = ["onCreate","onClick","onResume"]
    counter = 0
    counter1 = 0
    data_collect=readJson(data_collect_path)
    for key in data_collect.keys():
        if(len(data_collect[key]["used"])>0):
            res[key]={}
            res[key]["used"]=[]
            used=data_collect[key]["used"]
            for scene in used:
                counter+=1
                existed=False
                for chain in scene["invoke_chain"]:
                    for event in event_key:
                        if event in chain:
                            existed=True
                            break
                    if existed:
                        break
                if existed:
                    counter1 += 1
                    res[key]["used"].append(scene)
                else:
                    continue
        else:
            res[key]=data_collect[key]
    writeJson(res,out_put_path)
    print("data_collect_filter3:")
    print("削减前：", counter, " 削减后：", counter1)

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
        if len(used)>0:
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
        used = scenes[i]["used"]
        if len(used) > 0:
            sinks.add(i)
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
                        cg["edges"][edge_key]["info"] = {"source": parent_id, "target": child_id, "id": tmp}
                        cg['edges'][edge_key]["call_sum"] = 1
                        edge_id += 1
    G=ig.Graph(directed=True)
    nodes = []
    for i in cg["nodes"].keys():
        nodes.append(cg["nodes"][i])
    edges=[]
    for i in cg["edges"].keys():
        o_edge=cg["edges"][i]
        t_edge=(o_edge["info"]["source"],o_edge["info"]["target"])
        edges.append(t_edge)
    G.add_vertices(nodes)
    G.add_edges(edges)
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
            s=set(G.subcomponent(i,mode="out"))
            t=set(G.subcomponent(j,mode="in"))
            n=s.intersection(t)
            one_path=[]
            for m in n:
                one_path.append(node_retravers[m])
            source_to_sink.append(one_path)
    return source_to_sink


def getClass(sig):
    "".split()
    return sig.split(":")[0][1:]

def length(e):
    return len(e)

def getClasses(source_to_sink,output):
    classes=[]
    for i in source_to_sink:
        clazz_one_time = set()
        for sig in i:
            clazz=getClass(sig)
            clazz_one_time.add(clazz)
        classes.append(list(clazz_one_time))

    list_len = []
    list.sort(classes, key=length)
    for i in range(len(classes)):
        b = False
        for j in range(i + 1, len(classes)):
            if set(classes[i]).issubset(classes[j]):
                b = True
        if not b:
            list_len.append(classes[i])

    try:
        f = open(os.path.join(output, "activity_trans_graph.json"), "r")
        content = json.load(f)
        f.close()
        for key in content.keys():
            tmp = []
            tmp.append(key)
            for i in content[key]:
                tmp.append(i)
            list_len.append(tmp)
    except:
        pass
    f=open(os.path.join(output,"class.json"),"w",encoding="utf-8")
    json.dump(list_len,f)
    f.close()
    return list_len
def main(api_used,sensitive_scenes,output):
    data_deleted=os.path.join(output,"data_deleted.json")
    data_collect_filter3(api_used,data_deleted)
    scenes_deleted=os.path.join(output,"scenes_deleted.json")
    data_collect_filter3(sensitive_scenes,scenes_deleted)
    source_to_sink = find_pathes(data_deleted,scenes_deleted)
    getClasses(source_to_sink, output)

if __name__ == '__main__':
    api_used=str(sys.argv[1])
    sensitive_scenes=str(sys.argv[2])
    output=str(sys.argv[3])
    main(api_used,sensitive_scenes,output)







