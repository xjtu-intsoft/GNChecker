#!/usr/bin/env python
# _*_ coding: utf-8 _*_

import os

import requests
import json
url = "https://api.gptapi.us/v1/chat/completions"
model = "gpt-3.5-turbo"
<<<<<<< HEAD
api_key="sk-lSF0BphfJ9Qha7oCFaEf5cFf194f4f60A87aA27cD1A5E6F4"## 密钥
=======
api_key=""## 密钥
>>>>>>> e086281cb33090264fdc6a87e4e02a9ae8280ffa

headers = {
    'Accept': 'application/json',
    'Authorization': 'Bearer '+api_key,
    'User-Agent': 'Apifox/1.0.0 (https://apifox.com)',
    'Content-Type': 'application/json'
}

def one_chat(message):
    """
    :param message:  {
                "role": "user",
                "content": '请分析以下文本，并严格按照示例输出，不要多余总结信息。文本："\阿里一建登陆SDK\n一键登录功能，我们使用了阿里巴巴公司的号码速验SDK，方便识别用户的手机号码用于号码认证和快速登录（包括移动、电信、联通）\n个人常用设备信息\n取网络类型、设备信息（IP地址、设备制造商、设备型号、IMEI、手机操作系统、应用程序供应商标志符（IDFV）、SIM卡或国际移动用户识别码（IMSI）信息）的权限\nAPP初始化SDK,SDK通过自己逻辑调用系统的API获取\nhttp://terms.aliyun.com/legal-agreement/terms/suit_bu1_ali_cloud/suit_bu1_ali_cloud201902141711_54837.html?\nspm=a2c4g.11186623.0.0.3bff633e9gmrxp
                }
    :return: 若成功，则返回分析结果，否则则返回错误代码
    """
    messages=[{
                "role": "system",
                "content": '你现在是一个隐私政策文本分析师，需要你从一段隐私政策本文中抽取该隐私政策声明了哪些服务商会收集哪些信息并发送到什么位置;最后以python列表的形式输出'
                           '示例1：输入文本：微信支付 SDK（仅限安卓app）服务商名称：财付通支付科技有限公司权限：电话对应业务功能：帮助用户在应用内使用微信支付必要性说明：标识设备唯一性，甄别设备 安全信息类型：设备信息：包含国际移动设备识别码（IMEI）、安卓ID、IMSI信息、OPENUDID、GUID、Mac地址SDK隐私政策链接：https://www.tenpay.com/v3/helpcenter/low/privacy.shtml处理方式：采用去标识化、加密传输等安全处理方式。\n 最后以python列表的形式输出：[{"服务商":"微信支付 SDK","信息类型":["设备信息","IMEI","安卓ID","IMSI信息","OPENUDID","GUID","Mac地址"],"发送位置":"https://www.tenpay.com/"}]。'
                           '示例2：输入文本：声网语音服务 SDK\n功能：帮助用户参与房间聊天以及连麦等\n收集个人信息类型：设备标识符，MAC地址，录音麦克风权限，网络状态\n隐私权政策链接：https://www.shengwang.cn/SDK-privacy-policy/。\n 最后以python字典的形式输出：[{"服务商":"声网语音服务 SDK","信息类型":["设备标识符,"MAC地址","录音麦克风权限","网络状态"],"发送位置":"https://www.shengwang.cn"}]。'
                           '示例3：输入文本：同时，我们也会使用第三方SDK实现以上采集和使用，其中，如您使用小米、魅族、华为、OPPO、VIVO手机的，腾讯视频接入的上述手机厂商Push SDK需要收集手机唯一标识信息（例如IMEI），并可能会收集您的手机型号、系统类型、系统版本、设备屏幕尺寸等参数用于实现推广活动、视频内容等信息的推送；我们还会使用艾瑞咨询集团的SDK进行播放统计，该SDK可能会收集您的手机唯一标识信息（例如IMEI）以及视频播放记录、系统版本、手机型号等参数用于完成上述统计。\nTrueDepth APIs仅会获取人脸在世界坐标系的位置，用于实时计算眼睛到屏幕的距离，我们既不会存储也不会与第三方共享该信息。\n为提升您的用户体验，例如优化广告效果，我们需要向第三方合作伙伴等，分享已经匿名化或去标识化处理后的信息，要求其严格遵守我们关于数据隐私保护的措施与要求，包括但不限于根据数据保护协议、承诺书及相关数据处理政策进行处理，避免识别出个人身份，保障隐私安全。\n我们不会向合作伙伴分享可用于识别您个人身份的信息（例如您的姓名或电子邮件地址），除非您明确授权。\n另外，根据相关法律法规及国家标准，以下情形中，我们可能会共享、转让、公开披露个人信息无需事先征得您的授权同意：\n\t\t\t请通过 https://kf.qq.com/ 与我们联系。\n您也可以将您的问题发送至Dataprivacy@tencent.com或寄到如下地址：\n\t\t\t中国广东省深圳市南山区科技中一路腾讯大厦 法务部 数据及隐私保护中心（收）\n\t\t\t邮编：518057\n。 最后以python字典的形式输出：[{"服务商": "腾讯视频接入的上述手机厂商Push SDK","信息类型": ["手机唯一标识信息", "IMEI", "手机型号", "系统类型", "系统版本", "设备屏幕尺寸"],"发送位置":"无"},{"服务商": "艾瑞咨询集团的SDK","信息类型": ["手机唯一标识信息", "IMEI", "视频播放记录", "系统版本", "手机型号"],"发送位置": "无"},{"服务商": "TrueDepth APIs","信息类型": ["人脸在世界坐标系的位置"],"发送位置": "无"},{"服务商": "第三方合作伙伴","信息类型": ["已匿名化或去标识化处理后的信息"],"发送位置": "无"},{"服务商": "腾讯","信息类型": ["个人信息"],"发送位置": "无"}]'
                           '示例4：输入文本：一、我们如何收集和使用您的个人信息二、我们如何使用Cookie和同类技术三、我们如何共享、转让、公开披露您的个人信息四、我们如何保护您个人信息的安全五、管理您的个人信息六、我们如何处理儿童的个人信息。\n 最后以python字典的形式输出：[]'
                           '示例5：输入文本：2、百度应用分析SDK百度应用分析SDK获取的个人信息：设备信息（获取手机状态信息/ip/WIFI的SSID/WIFI的BSSID/设备序列号/IMEI/IMSI/MAC/Android ID/IDFA/OpenUDID/GUID/SIM卡IMSI/地理位置/安装列表/OAID）使用SDK目的：统计哪个功能用户经常使用使用SDK方式范围：首页加载百度应用分析SDK隐私权政策链接：https://tongji.baidu.com/web/help/article?id=330&type=0。\n 最后以python字典的形式输出：{"服务商": "百度人脸识别SDK","信息类型": ["手机状态信息","IP","WIFI的SSID","WIFI的BSSID","设备序列号","IMEI","IMSI","MAC","Android ID","IDFA","OpenUDID","GUID","SIM卡IMSI","地理位置","安装列表","OAID","用户姓名","身份证","人脸照片"],"发送位置": "https://ai.baidu.com/ai-doc/REFERENCE/Vkdygjliz"}'

                }]
    messages.append(message)
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.2,
    })
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code==200:
        res_data=json.loads(response.text)
        if res_data["choices"][0]["finish_reason"]=="stop" or res_data["choices"][0]["finish_reason"]==None:
            try:
                content = res_data["choices"][0]["message"]["content"]
                start_index = content.find("```")
                if start_index == -1:
                    return {"data":json.loads(content)}
                end_index = content.find("```", start_index + 3)
                dic = content[start_index + 3:end_index]
                dic = dic.replace("python", "")
                return {"data": json.loads(dic)}
            except:
                response = requests.request("POST", url, headers=headers, data=payload)
                if response.status_code == 200:
                    res_data = json.loads(response.text)
                    if res_data["choices"][0]["finish_reason"] == "stop":
                        try:
                            content = res_data["choices"][0]["message"]["content"]
                            start_index = content.find("```")
                            if start_index == -1:
                                return {"data":json.loads(content)}
                            end_index = content.find("```", start_index + 3)
                            dic = content[start_index + 3:end_index]
                            dic = dic.replace("python", "")
                            return {"data": json.loads(dic)}
                        except:
                            return {"error_code": "error"}
                    else:
                        return {"error_code": res_data["choices"]["finish_reason"]}
                else:
                    return {"error_code": response.status_code}
        else:
            return {"error_code":res_data["choices"][0]["finish_reason"]}
    else:
        return {"error_code":response.status_code}

def one_policy(cut_strings_json):
    f = open(cut_strings_json, "r", encoding="utf-8")
    content=json.load(f)
    f.close()
    starts_words = '请分析以下文本，并严格按照示例输出（python列表形式），不要多余总结信息。请分析完全，并输出完整。文本：'
    error=[]
    res=[]
    for i in content:
        message_content=starts_words+i
        message = {
            "role": "user",
            "content": message_content
        }
        response=one_chat(message)
        if "error_code" in response.keys():
            error.append({"error":response["error_code"]})
        else:
            res.extend(response["data"])
    return res,error

def scale_batch_process(root):
    count=0
    for i in os.listdir(root):
        # if count>100:
        #     break
        print("current file is -----",i)
        cut_strings_path=os.path.join(root,i,"cut_strings_new.json")
        third_party_info_path=os.path.join(root,i,"third_party_info.json")
        if os.path.exists(third_party_info_path):
            print(i, " has been analysed!!!")
            continue
        res,error=one_policy(cut_strings_path)
        f=open(third_party_info_path,"w",encoding="utf-8")
        json.dump({"third_party":res,"error_info":error},f,ensure_ascii=False)
        f.close()
        print(i," successfully analysed!!!")
        count+=1


if __name__=="__main__":
<<<<<<< HEAD

    scale_batch_process(r"D:\cert\实验\dataset\predict")
=======
    pp_root=""
    scale_batch_process(pp_root)
>>>>>>> e086281cb33090264fdc6a87e4e02a9ae8280ffa


