package my;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.resources.LayoutFileParser;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JStaticInvokeExpr;
import soot.util.Chain;

import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * @description:
 * @author: xxx
 * @date: 2023/11/12 23:54
 **/
public class FindDataTransmission1 {

    public static List<Map> findCrossAppTransPlus1(String packageName, Map<String,Long> nodes, Map<Long,String> nodeReverse, Map<Long,List> parents_info) {
        /**
         * @description: 定位跨app数据传输的函数
         * @author: xxx
         * @date: 2022/12/9 14:52
         * @param:
         * @param: cg
         * @return: List<Map>
         **/
        List<Map> result = new ArrayList<>();
        //app跳转
        List<List> pathes = Util.getPathes("<android.content.Context: void startActivity(android.content.Intent)>", nodes,nodeReverse,parents_info);
        pathes.addAll(Util.getPathes("<android.app.Activity: void startActivity(android.content.Intent)>", nodes,nodeReverse,parents_info));
        for (int i = 0; i < pathes.size(); i++) {
            try {
                List chain=pathes.get(i);
                String parent = (String) chain.get(chain.size()-2);
                SootMethod source = Scene.v().grabMethod(parent);
                Body body = source.retrieveActiveBody();
                UnitPatchingChain bodyUnits = body.getUnits();
                Iterator<Unit> unitIterator = bodyUnits.iterator();
                while (unitIterator.hasNext()) {
                    Unit next = unitIterator.next();
                    if (next.getClass().getSimpleName().equals("JInvokeStmt")) {
                        JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                        InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                        String methodRef = invokeExpr.getMethodRef().toString();
                        if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>")) {
                            Value arg = invokeExpr.getArg(1);
                            String argType = arg.getClass().getSimpleName();
                            if (argType.equals("JimpleLocal")) {
                                Iterator<Unit> iterator1 = bodyUnits.iterator();
                                while (iterator1.hasNext()) {
                                    Unit next1 = iterator1.next();
                                    if (next1.getClass().getSimpleName().equals("JAssignStmt")) {
                                        JAssignStmt jIAssiStmt = (JAssignStmt) next1;
                                        if (jIAssiStmt.getLeftOp().equals(arg)) {
                                            Value rightOp = jIAssiStmt.getRightOp();
                                            if (rightOp.getClass().getSimpleName().equals("JStaticInvokeExpr")) {
                                                JStaticInvokeExpr rightOp1 = (JStaticInvokeExpr) rightOp;
                                                if (rightOp1.getMethodRef().toString().equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
                                                    Value arg1 = rightOp1.getArg(0);
                                                    if (arg.getClass().getSimpleName().equals("StringConstant")) {
                                                        String s = arg.toString();
                                                        String argStr = s.substring(1, s.length() - 1);
                                                        if (!argStr.contains(packageName)) {
                                                            Map<String, Object> map = new HashMap<>();
                                                            map.put("type", "UrlScheme");
                                                            map.put("target", argStr);
                                                            map.put("invoke_chain",chain);
                                                            //intent 携带数据待补充
                                                            String data = "";
                                                            map.put("data", data);
                                                            result.add(map);
                                                        }
                                                    }else {
                                                        //是否补充有待商榷
                                                        Map<String, Object> map = new HashMap<>();
                                                        map.put("type", "UrlScheme");
                                                        map.put("target", "");
                                                        map.put("invoke_chain",chain);
                                                        //intent 携带数据待补充
                                                        String data = "";
                                                        map.put("data", data);
                                                        result.add(map);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                }
                            } else if (argType.equals("JInvokeExpr")) {
                                //待补充
                            }
                        }
                        //init() setAction()
                        else if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String)>") || methodRef.equals("<android.content.Intent: android.content.Intent setAction(java.lang.String)>")) {
                            Value arg = invokeExpr.getArg(0);
                            String s = arg.toString();
                            String argStr = s.substring(1, s.length() - 1);
                            //SEND类型
                            if (argStr.equals("android.intent.action.SEND")) {
                                Map<String, Object> map = new HashMap<>();
                                map.put("type", "android.intent.action.SEND");
                                map.put("target", "");
                                map.put("invoke_chain",chain);
                                //intent 携带数据待补充
                                String data = "";
                                map.put("data", data);
                                result.add(map);
                            }
                        }
                        //显示跳转 setClassName()
                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setClassName(java.lang.String,java.lang.String)>") || methodRef.equals("<android.content.Intent: android.content.Intent setClassName(android.content.Context,java.lang.String)>")) {
                            Value arg1 = invokeExpr.getArg(1);
                            if (arg1.getClass().getSimpleName().equals("StringConstant")) {
                                String s = arg1.toString();
                                String argStr = s.substring(1, s.length() - 1);
                                if (!argStr.contains(packageName)) {
                                    Map<String, Object> map = new HashMap<>();
                                    map.put("type", "setClassName");
                                    map.put("target", argStr);
                                    map.put("invoke_chain",chain);
                                    //intent 携带数据待补充
                                    String data = "";
                                    map.put("data", data);
                                    result.add(map);
                                }
                            }
                        }
                        //setComponent()
                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setComponent(android.content.ComponentName)>")) {
                            Iterator<Unit> iterator1 = bodyUnits.iterator();
                            while (iterator1.hasNext()) {
                                Unit next1 = iterator1.next();
                                if (next1.getClass().getSimpleName().equals("JInvokeStmt")) {
                                    JInvokeStmt jInvokeStmt1 = (JInvokeStmt) next1;
                                    InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
                                    String methodRef1 = invokeExpr1.getMethodRef().toString();
                                    //Componentname(str,str)||Componentname(context,str)
                                    if (methodRef1.equals("<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>") || methodRef1.equals("<android.content.ComponentName: void <init>(android.content.Context,java.lang.String)>")) {
                                        Value arg = invokeExpr1.getArg(1);
                                        if (arg.getClass().getSimpleName().equals("StringConstant")) {
                                            String s = arg.toString();
                                            String argStr = s.substring(1, s.length() - 1);
                                            if (!argStr.contains(packageName)) {
                                                Map<String, Object> map = new HashMap<>();
                                                map.put("type", "setComponentName");
                                                map.put("target", argStr);
                                                map.put("invoke_chain",chain);
                                                //intent 携带数据待补充
                                                String data = "";
                                                map.put("data", data);
                                                result.add(map);
                                            }
                                        }
                                        break;
                                    } else if (methodRef1.equals(methodRef)) {
                                        break;
                                    }

                                }
                            }

                        }
                        //urlScheme
                        else if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>")) {
                            Iterator<Unit> iterator1 = bodyUnits.iterator();
                            while (iterator1.hasNext()) {
                                Unit next1 = iterator1.next();
                                if (next1.getClass().getSimpleName().equals("JInvokeStmt")) {
                                    JInvokeStmt jInvokeStmt1 = (JInvokeStmt) next1;
                                    InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
                                    String methodRef1 = invokeExpr1.getMethodRef().toString();
                                    //Componentname(str,str)||Componentname(context,str)
                                    if (methodRef1.equals("<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>") || methodRef1.equals("<android.content.ComponentName: void <init>(android.content.Context,java.lang.String)>")) {
                                        Value arg = invokeExpr1.getArg(1);
                                        if (arg.getClass().getSimpleName().equals("StringConstant")) {
                                            String s = arg.toString();
                                            String argStr = s.substring(1, s.length() - 1);
                                            if (!argStr.contains(packageName)) {
                                                Map<String, Object> map = new HashMap<>();
                                                map.put("type", "setComponentName");
                                                map.put("target", argStr);
                                                map.put("invoke_chain",chain);
                                                //intent 携带数据待补充
                                                String data = "";
                                                map.put("data", data);
                                                result.add(map);
                                            }
                                        }
                                        break;
                                    } else if (methodRef1.equals(methodRef)) {
                                        break;
                                    }

                                }
                            }
                        }
                    }

                }
            }catch (Exception e){
                continue;
            }

        }

        return result;
    }
    public static List<Map> findCrossCountryTransPlus1(List<Map> netTrans){
        ArrayList<Map> results = new ArrayList<>();
        return results;
    }
    public static List<Map> findNetTransPlus(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info, String packageName,String regexPath){
        ArrayList<Map> results = new ArrayList<>();
        //正则pattern
        List<String> regexes = Util.readFile(regexPath);
        Pattern ipRegex = Pattern.compile(regexes.get(0));
        Pattern urlRegex = Pattern.compile(regexes.get(1));
        Pattern urlRegex1 = Pattern.compile(regexes.get(2));
        List<String> netTransAPI = findNetTransAPI(nodes);
        for(int i=0;i<netTransAPI.size();i++){
            String api = netTransAPI.get(i);
            List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
            Set<String> pathesSet=new HashSet<>();
            for(int j=0;j<pathes.size();j++){
                List list = pathes.get(j);
                String pathStr = list.toString();
                if(!pathesSet.contains(pathStr)){
                    pathesSet.add(pathStr);
                    String source="";
                    for(int n=0;n<list.size();n++){
                        try {
                            source=source+Util.getMethodBody(list.get(n).toString());
                        }catch (Exception e){
                            continue;
                        }
                    }
                    Map<String, Set> urlMap = Util.urlRegexMatching(source, ipRegex, urlRegex, urlRegex1);
                    String target="";
                    Set ip = urlMap.get("ip");
                    Set url = urlMap.get("url");
                    if(!ip.isEmpty()||!url.isEmpty()){
                        target=ip.toString()+" "+url.toString();
                        target=target.replace("[","");
                        target=target.replace("]","");
                    }
                    //设计方法规则找到data,url
                    Map<String, Object> map = new HashMap<>();
                    map.put("api",api);
                    map.put("target",target);
                    map.put("net_target_info", urlMap);
                    map.put("invoke_chain", list);
                    results.add(map);
                }
            }
        }
        return results;
    }
    public static List<String> findNetTransAPI(Map<String,Long> nodes){
        ArrayList<String> res = new ArrayList<>();
        res.add("<java.net.URLConnection: void connect()>");
        res.add("<java.net.URL: java.net.URLConnection openConnection()>");
        res.add("<okhttp3.HttpUrl: okhttp3.HttpUrl get(java.net.URL)>");
        res.add("<okhttp3.HttpUrl: okhttp3.HttpUrl get(java.net.URI)>");
        res.add("<java.net.Socket: void connect(java.net.SocketAddress,int)>");
        return res;
    }
    public static List<Map> findDataIntoFilePlus1(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        ArrayList<Map> results = new ArrayList<>();
        List<String> dataEnencodeApi = findFileWriteApi(nodes);
        for(int i=0;i<dataEnencodeApi.size();i++){
            if(results.size()>1000){
                break;
            }
            String api = dataEnencodeApi.get(i);
            List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
            Set<String> pathesSet=new HashSet<>();
            for(int j=0;j<pathes.size();j++){
                List list = pathes.get(j);
                String pathStr = list.toString();
                if(!pathesSet.contains(pathStr)){
                    pathesSet.add(pathStr);
                    Map<String, Object> map = new HashMap<>();
                    map.put("api",api);
                    map.put("target","");
                    map.put("invoke_chain", list);
                    results.add(map);
                }
            }
        }
        return results;
    }

    private static List<String> findFileWriteApi(Map<String, Long> nodes) {
        ArrayList<String> results = new ArrayList<>();
        results.add("<java.io.FileOutputStream: void write(byte[])>");
        results.add("<java.io.FileOutputStream: void write(byte[],int,int)>");
        return results;
    }
    public static List<Map> findDataIntoDBPlus1(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        //插入
        //<android.database.sqlite.SQLiteDatabase: long insert(java.lang.String,java.lang.String,android.content.ContentValues)>
        // <android.database.sqlite.SQLiteDatabase: long insertOrThrow(java.lang.String,java.lang.String,android.content.ContentValues)>
        //<android.database.sqlite.SQLiteDatabase: long insertWithOnConflict(java.lang.String,java.lang.String,android.content.ContentValues,int)>
        //替换
        //<android.database.sqlite.SQLiteDatabase: long replace(java.lang.String,java.lang.String,android.content.ContentValues)>
        //<android.database.sqlite.SQLiteDatabase: long replaceOrThrow(java.lang.String,java.lang.String,android.content.ContentValues)>
        //更新
        //<android.database.sqlite.SQLiteDatabase: int update(java.lang.String,android.content.ContentValues,java.lang.String,java.lang.String[])>
        //<android.database.sqlite.SQLiteDatabase: int updateWithOnConflict(java.lang.String,android.content.ContentValues,java.lang.String,java.lang.String[],int)>
        ArrayList<Map> results = new ArrayList<>();
        List<String> insertApi=new ArrayList<>();
        insertApi.add("<android.database.sqlite.SQLiteDatabase: long insert(java.lang.String,java.lang.String,android.content.ContentValues)>");
        insertApi.add("<android.database.sqlite.SQLiteDatabase: long insertOrThrow(java.lang.String,java.lang.String,android.content.ContentValues)>");
        insertApi.add("<android.database.sqlite.SQLiteDatabase: long insertWithOnConflict(java.lang.String,java.lang.String,android.content.ContentValues,int)>");
        List<List> insertParents = new ArrayList<>();
        for(String api:insertApi){
            insertParents.addAll(Util.getPathes(api,nodes,nodeReverse,parents_info));
        }
        for(List chain:insertParents){
            String parent = (String) chain.get(chain.size() - 2);
            Body methodBody = Util.getMethodBody(parent);
            UnitPatchingChain bodyUnits = methodBody.getUnits();
            Iterator<Unit> unitIterator = bodyUnits.iterator();
            while (unitIterator.hasNext()){
                Unit next = unitIterator.next();
                if(next instanceof JInvokeStmt){
                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                    String methodRef = invokeExpr.getMethodRef().toString();
                    if(insertApi.contains(methodRef)){
                        Value arg = invokeExpr.getArg(0);
                        String argStr = arg.toString();
                        Map<String, Object> map = new HashMap<>();
                        map.put("type","insert");
                        map.put("api",methodRef);
                        map.put("target", argStr);
                        map.put("invoke_chain",chain);
                        //intent 携带数据待补充
                        String data = "";
                        map.put("data", data);
                        results.add(map);
                    }
                }
            }

        }
        return results;

    }
    public static List<Map> findDataIntoSmsPlus(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        List<Map> results=new ArrayList<>();
        List<String> smsApi=new ArrayList<>();
        smsApi.add("<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>");
        smsApi.add("<android.telephony.SmsManager: void sendDataMessage(java.lang.String,java.lang.String,short,byte[],android.app.PendingIntent,android.app.PendingIntent)>");
        smsApi.add("<android.telephony.SmsManager: void sendMultipartTextMessage(java.lang.String,java.lang.String,java.util.ArrayList,java.util.ArrayList,java.util.ArrayList)>");
        List<List> smsPathes=new ArrayList<>();
        for(String api : smsApi){
            smsPathes.addAll(Util.getPathes(api,nodes,nodeReverse,parents_info));
        }
        for(List chain :smsPathes){
            String parent=(String)chain.get(chain.size()-2);
            Body methodBody = Util.getMethodBody(parent);
            UnitPatchingChain bodyUnits = methodBody.getUnits();
            Iterator<Unit> unitIterator = bodyUnits.iterator();
            while (unitIterator.hasNext()){
                Unit next = unitIterator.next();
                if(next instanceof JInvokeStmt){
                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                    String methodRef = invokeExpr.getMethodRef().toString();
                    if(smsApi.contains(methodRef)){
                        Value arg = invokeExpr.getArg(0);
                        String argStr = arg.toString();
                        Map<String, Object> map = new HashMap<>();
                        map.put("type","sms");
                        map.put("api",methodRef);
                        map.put("target", argStr);
                        map.put("invoke_chain",chain);
                        //intent 携带数据待补充
                        String data = "";
                        map.put("data", data);
                        results.add(map);
                    }
                }
            }

        }
        return results;
    }
    public static List<Map> findDataEncodeTransPlus(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        ArrayList<Map> results = new ArrayList<>();
        List<String> dataEnencodeApi = findEncodeApi(nodes);
        for(int i=0;i<dataEnencodeApi.size();i++){
            String api = dataEnencodeApi.get(i);
            List<List> pathes = Util.getPathes(api,nodes,nodeReverse,parents_info);
            Set<String> pathesSet=new HashSet<>();
            for(int j=0;j<pathes.size();j++){
                List list = pathes.get(j);
                String pathStr = list.toString();
                if(!pathesSet.contains(pathStr)){
                    pathesSet.add(pathStr);
                    Map<String, Object> map = new HashMap<>();
                    map.put("api",api);
                    map.put("target","");
                    map.put("invoke_chain", list);
                    results.add(map);
                }
            }
        }
        return results;
    }
    public static List<String> findEncodeApi(Map<String,Long> nodes){
        ArrayList<String> results = new ArrayList<>();
        results.add("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[])>");
        results.add("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[],int)>");
//        results.add("<javax.crypto.Cipher: int doFinal(java.nio.ByteBuffer,java.nio.ByteBuffer)>");
//        results.add("<javax.crypto.Cipher: byte[] doFinal(byte[],int,int)>");
//        results.add("<java.security.Signature: java.security.Signature getInstance(java.lang.String)>");
        return results;
    }
}
