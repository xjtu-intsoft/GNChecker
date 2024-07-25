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
 * @description: 定位数据上传，跨app传输数据函数位置
 * @author: xxx
 * @date: 2022/12/7 16:06
 **/
public class FindDataTransmission {

    private static String readerMethod(File file) throws IOException {
        FileReader fileReader = new FileReader(file);
        Reader reader = new InputStreamReader(new FileInputStream(file), "Utf-8");
        int ch = 0;
        StringBuffer sb = new StringBuffer();
        while ((ch = reader.read()) != -1) {
            sb.append((char) ch);
        }
        fileReader.close();
        reader.close();
        String jsonStr = sb.toString();
        return jsonStr;    
    }
    public static void singleApkAnalyze(String apk) throws XmlPullParserException, IOException {
        InfoflowAndroidConfiguration conf = new InfoflowAndroidConfiguration();
        // androidDirPath是你的android sdk中platforms目录的路径
        conf.getAnalysisFileConfig().setAndroidPlatformDir("C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms");
        // apkFilePath是你要分析的apk的文件路径
//        conf.getAnalysisFileConfig().setSourceSinkFile("C:\\Users\\77294\\Desktop\\cert_境外非法传输+数据使用目的分析\\input\\SourcesAndSinks.txt");
        conf.getAnalysisFileConfig().setTargetAPKFile(apk);
        // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
        conf.setMergeDexFiles(true);
        // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
        conf.getAccessPathConfiguration().setAccessPathLength(-1);
        // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
        conf.getSolverConfiguration().setMaxAbstractionPathLength(-1);
        conf.getPathConfiguration().setMaxCallStackSize(-1);
        conf.getPathConfiguration().setMaxPathLength(-1);

        SetupApplication setup = new SetupApplication(conf);
        // 设置Callback的声明文件（不显式地设置好像FlowDroid会找不到）
//        setup.setCallbackFile("C:\\Users\\77294\\Desktop\\flowdroid\\FlowDroid-develop\\soot-infoflow-android\\AndroidCallbacks.txt");
        setup.initializeSoot();
        setup.parseAppResources();
        String packageName = setup.getMainfest().getPackageName();
        Chain<SootClass> applicationClasses = Scene.v().getApplicationClasses();
//        CallGraph cg = new CallGraph();
//        Util.callGraphGenerate(applicationClasses, cg);
//        System.out.println(cg.toString());
//        List<Map> crossAppTrans = findCrossAppTrans(cg, packageName);
//        Util.writeListToJson("F:\\output2\\"+packageName+".json", crossAppTrans, false);
//        System.out.println(crossAppTrans);

    }
    public static List<Map> findCrossAppTransPlus1(String packageName,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info) {
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
    public static List<Map> findCrossAppTransPlus(String packageName,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info) {
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

        //broadcast
//        Set<String> broadcastMethodSig = broadcastMethodSig();
//        Iterator<String> iterator = broadcastMethodSig.iterator();
//        while (iterator.hasNext()){
//            String next = iterator.next();
//            List<List> broadPathes = Util.getPathes(next, nodes,nodeReverse,parents_info);
//            for(int i=0;i<broadPathes.size();i++){
//                List chain = broadPathes.get(i);
//                String parent = (String) chain.get(chain.size()-2);
//                SootMethod source = Scene.v().grabMethod(parent);
//                Body body = source.retrieveActiveBody();
//                UnitPatchingChain bodyUnits = body.getUnits();
//                Iterator<Unit> unitIterator = bodyUnits.iterator();
//                Boolean notFindTaret=true;
//                while (unitIterator.hasNext()) {
//                    Unit next1 = unitIterator.next();
//                    if (next.getClass().getSimpleName().equals("JInvokeStmt")) {
//                        JInvokeStmt jInvokeStmt = (JInvokeStmt) next1;
//                        InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
//                        String methodRef = invokeExpr.getMethodRef().toString();
//                        if (methodRef.equals("<android.content.Intent: void <init>(java.lang.String,android.net.Uri)>")) {
//                            Value arg = invokeExpr.getArg(1);
//                            String argType = arg.getClass().getSimpleName();
//                            if (argType.equals("JimpleLocal")) {
//                                Iterator<Unit> iterator1 = bodyUnits.iterator();
//                                while (iterator1.hasNext()) {
//                                    Unit next11 = iterator1.next();
//                                    if (next1.getClass().getSimpleName().equals("JAssignStmt")) {
//                                        JAssignStmt jIAssiStmt = (JAssignStmt) next11;
//                                        if (jIAssiStmt.getLeftOp().equals(arg)) {
//                                            Value rightOp = jIAssiStmt.getRightOp();
//                                            if (rightOp.getClass().getSimpleName().equals("JStaticInvokeExpr")) {
//                                                JStaticInvokeExpr rightOp1 = (JStaticInvokeExpr) rightOp;
//                                                if (rightOp1.getMethodRef().toString().equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
//                                                    Value arg1 = rightOp1.getArg(0);
//                                                    if (arg.getClass().getSimpleName().equals("StringConstant")) {
//                                                        String s = arg.toString();
//                                                        String argStr = s.substring(1, s.length() - 1);
//                                                        if (!argStr.contains(packageName)) {
//                                                            notFindTaret=false;
//                                                            Map<String, Object> map = new HashMap<>();
//                                                            map.put("type", "Broadcast");
//                                                            map.put("target", argStr);
//                                                            map.put("invoke_chain",chain);
//                                                            map.put("sendType",next);
//                                                            //intent 携带数据待补充
//                                                            String data = "";
//                                                            map.put("data", data);
//                                                            result.add(map);
//                                                        }
//                                                    }else {
//                                                        //是否补充有待商榷
//                                                        notFindTaret=false;
//                                                        Map<String, Object> map = new HashMap<>();
//                                                        map.put("type", "Broadcast");
//                                                        map.put("target", "");
//                                                        map.put("invoke_chain",chain);
//                                                        //intent 携带数据待补充
//                                                        String data = "";
//                                                        map.put("data", data);
//                                                        result.add(map);
//                                                    }
//                                                }
//                                            }
//                                        }
//
//
//                                    }
//
//                                }
//                            } else if (argType.equals("JInvokeExpr")) {
//                                //待补充
//                            }
//                        }
//                        //显示跳转 setClassName()
//                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setClassName(java.lang.String,java.lang.String)>") || methodRef.equals("<android.content.Intent: android.content.Intent setClassName(android.content.Context,java.lang.String)>")) {
//                            Value arg1 = invokeExpr.getArg(1);
//                            if (arg1.getClass().getSimpleName().equals("StringConstant")) {
//                                String s = arg1.toString();
//                                String argStr = s.substring(1, s.length() - 1);
//                                if (!argStr.contains(packageName)) {
//                                    notFindTaret=false;
//                                    Map<String, Object> map = new HashMap<>();
//                                    map.put("type", "Broadcast");
//                                    map.put("target", argStr);
//                                    map.put("invoke_chain",chain);
//                                    map.put("sendType",next);
//                                    //intent 携带数据待补充
//                                    String data = "";
//                                    map.put("data", data);
//                                    result.add(map);
//                                }
//                            }
//                        }
//                        //setComponent()
//                        else if (methodRef.equals("<android.content.Intent: android.content.Intent setComponent(android.content.ComponentName)>")) {
//                            Iterator<Unit> iterator1 = bodyUnits.iterator();
//                            while (iterator1.hasNext()) {
//                                Unit next11 = iterator1.next();
//                                if (next1.getClass().getSimpleName().equals("JInvokeStmt")) {
//                                    JInvokeStmt jInvokeStmt1 = (JInvokeStmt) next11;
//                                    InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
//                                    String methodRef1 = invokeExpr1.getMethodRef().toString();
//                                    //Componentname(str,str)||Componentname(context,str)
//                                    if (methodRef1.equals("<android.content.ComponentName: void <init>(java.lang.String,java.lang.String)>") || methodRef1.equals("<android.content.ComponentName: void <init>(android.content.Context,java.lang.String)>")) {
//                                        Value arg = invokeExpr1.getArg(1);
//                                        if (arg.getClass().getSimpleName().equals("StringConstant")) {
//                                            String s = arg.toString();
//                                            String argStr = s.substring(1, s.length() - 1);
//                                            if (!argStr.contains(packageName)) {
//                                                notFindTaret=false;
//                                                Map<String, Object> map = new HashMap<>();
//                                                map.put("type", "Broadcast");
//                                                map.put("target", argStr);
//                                                map.put("invoke_chain",chain);
//                                                map.put("sendType",next);
//                                                //intent 携带数据待补充
//                                                String data = "";
//                                                map.put("data", data);
//                                                result.add(map);
//                                            }
//                                        }
//                                        break;
//                                    } else if (methodRef1.equals(methodRef)) {
//                                        break;
//                                    }
//
//                                }
//                            }
//
//                        }
//
//
//                    }
//
//                }
//                if(notFindTaret){
//                    Map<String, Object> map = new HashMap<>();
//                    map.put("type", "Broadcast");
//                    map.put("target", "");
//                    map.put("invoke_chain",chain);
//                    map.put("sendType",next);
//                    //intent 携带数据待补充
//                    String data = "";
//                    map.put("data", data);
//                    result.add(map);
//                }
//
//            }
//
//        }

        //ContentProvider
//        List<List> contentProviderPathes = Util.getPathes("<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)>", nodes,nodeReverse,parents_info);
//        contentProviderPathes.addAll(Util.getPathes("<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])>",nodes,nodeReverse,parents_info));
//        for(int i=0;i<contentProviderPathes.size();i++){
//            List chain =contentProviderPathes.get(i);
//            String parent = (String) chain.get(chain.size()-2);
//            SootMethod source = Scene.v().grabMethod(parent);
//            Body body = source.retrieveActiveBody();
//            UnitPatchingChain bodyUnits = body.getUnits();
//
//            Iterator<Unit> unitIterator = bodyUnits.iterator();
//            String target="";
//            while (unitIterator.hasNext()) {
//                Unit next = unitIterator.next();
//                if (next.getClass().getSimpleName().equals("JInvokeStmt")) {
//                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
//                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
//                    String methodRef = invokeExpr.getMethodRef().toString();
//                    if (methodRef.equals("<android.content.ContentResolver: android.net.Uri insert(android.net.Uri,android.content.ContentValues)>")||methodRef.equals("<android.content.ContentResolver: int update(android.net.Uri,android.content.ContentValues,java.lang.String,java.lang.String[])>")) {
//                        Value arg = invokeExpr.getArg(0);
//                        String argType = arg.getClass().getSimpleName();
//                        if (argType.equals("JimpleLocal")) {
//                            Iterator<Unit> iterator1 = bodyUnits.iterator();
//                            while (iterator1.hasNext()) {
//                                Unit next1 = iterator1.next();
//                                if (next1.getClass().getSimpleName().equals("JAssignStmt")) {
//                                    JAssignStmt jIAssiStmt = (JAssignStmt) next1;
//                                    if (jIAssiStmt.getLeftOp().equals(arg)) {
//                                        Value rightOp = jIAssiStmt.getRightOp();
//                                        if (rightOp.getClass().getSimpleName().equals("JStaticInvokeExpr")) {
//                                            JStaticInvokeExpr rightOp1 = (JStaticInvokeExpr) rightOp;
//                                            if (rightOp1.getMethodRef().toString().equals("<android.net.Uri: android.net.Uri parse(java.lang.String)>")) {
//                                                Value arg1 = rightOp1.getArg(0);
//                                                if (arg.getClass().getSimpleName().equals("StringConstant")) {
//                                                    String s = arg.toString();
//                                                    target= s.substring(1, s.length() - 1);
//                                                }
//                                            }
//                                        }
//                                    }
//
//
//                                }
//
//                            }
//                        } else if (argType.equals("JInvokeExpr")) {
//                            //待补充
//                        }
//                    }
//                }
//
//            }
//            Map<String, Object> map = new HashMap<>();
//            map.put("type", "ContentProvider");
//            map.put("target", target);
//            map.put("invoke_chain",chain);
//            //intent 携带数据待补充
//            String data = "";
//            map.put("data", data);
//            result.add(map);
//
//        }
        return result;
    }
    public static List<Map> findCrossCountryTransPlus1(List<Map> netTrans){
        ArrayList<Map> results = new ArrayList<>();
        return results;
    }
    public static List<Map> findCrossCountryTransPlus(List<Map> netTrans){
        ArrayList<Map> results = new ArrayList<>();
        Client client = new Client();
        Map<String,Object> infoMap=new HashMap<>();
        for(Map simple:netTrans){
            Map target = (Map) simple.get("net_target_info");
            Set ips = (Set) target.get("ip");
            ArrayList<Map> ipList = new ArrayList<>();
            if(ips.size()>0){
                for(Object ip:ips){
                    try {
                        String targetIp="http://" + ip;
                        List<JsonObject> ip_info=null;
                        if(infoMap.containsKey(targetIp)){
                            ip_info=(List) infoMap.get(targetIp);
                        }else {
                            UrlInfo urlInfo = client.requestUrlParse("http://" + ip);
                            ip_info = urlInfo.getIp_info();
                            infoMap.put(targetIp,ip_info);
                        }
                        for(JsonObject tmp:ip_info){
                            JsonElement country_name = tmp.get("country_name");
                            String asString = country_name.getAsString();
                            if(asString.equals("\u4e2d\u56fd")||asString.equals("中国")){
                                continue;
                            }
                            else {
                                ipList.add(tmp.asMap());
                            }
                        }
                    }catch (Exception e){
                        continue;
                    }
                }
            }
            Set urls = (Set) target.get("url");
            ArrayList<Map> urlList = new ArrayList<>();
            if(urls.size()>0){
                for(Object url:urls){
                    String url1 = (String) url;
                    if(!url1.startsWith("http")){
                        url1="http://"+url1;
                    }
                    try {
                        List<JsonObject> ip_info=null;
                        if(infoMap.containsKey(url1)){
                            ip_info=(List) infoMap.get(url1);
                        }else {
                            UrlInfo urlInfo = client.requestUrlParse(url1);
                            ip_info = urlInfo.getIp_info();
                            infoMap.put(url1,ip_info);
                        }
                        for(JsonObject tmp:ip_info){
                            JsonElement country_name = tmp.get("country_name");
                            String asString = country_name.getAsString();
                            if(asString.equals("\u4e2d\u56fd")||asString.equals("中国")){
                                continue;
                            }
                            else {
                                HashMap<String, Object> map = new HashMap<>();
                                map.put("url",url);
                                map.put("ip_info",tmp);
                                urlList.add(map);
                            }
                        }
                    }catch (Exception e){
                        continue;
                    }


                }
            }
            if(ipList.size()>0||urlList.size()>0){
                HashMap<String, Object> map = new HashMap<>();
                map.put("invoke_chain",simple.get("invoke_chain"));
                map.put("data",simple.get("data"));
                map.put("api",simple.get("api"));
                map.put("target_ip",ipList);
                map.put("target_url",urlList);
                results.add(map);
            }
        }
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
                    //携带数据待补充
                    String data = "";
                    map.put("data", data);
                    results.add(map);
                }
            }
        }
        return results;
    }
    public static List<String> findNetTransAPI(Map<String,Long> nodes){
        int bound=0;
        ArrayList<String> results = new ArrayList<>();
        Set<String> classSet=new HashSet<>();
        Set<String> actionSet=new HashSet<>();
        classSet.add("http");classSet.add("socket");
        classSet.add("net");classSet.add("client");
        classSet.add("url");classSet.add("uri");
        actionSet.add("connect");actionSet.add("get");
        actionSet.add("post");actionSet.add("request");
        actionSet.add("execute");actionSet.add("connection");
        Iterator<String> iterator = nodes.keySet().iterator();
        Map<String,Map> methodMap=new HashMap();
        while (iterator.hasNext()){
            String next = iterator.next();
           try {
               SootMethod method = Scene.v().grabMethod(next);
               Map<String,String> map=new HashMap<>();
               map.put("class",method.getDeclaringClass().getShortName());
               map.put("method",method.getName());
               methodMap.put(method.getSignature(),map);
           }catch (Exception e){
               continue;
           }
        }
        Iterator<String> iterator1 = methodMap.keySet().iterator();
        while (iterator1.hasNext()){
            boolean a=false,b=false;
            String next = iterator1.next();
            Map map = methodMap.get(next);
            Iterator<String> iterator2 = classSet.iterator();
            while (iterator2.hasNext()){
                String next1 = iterator2.next();
                String aClass = (String) map.get("class");
                if(aClass==null){
                    break;
                }
                if(aClass.toLowerCase().contains(next1)){
                    a=true;
                    break;
                }
            }
            Iterator<String> iterator3 = actionSet.iterator();
            while (iterator3.hasNext()){
                String next1 = iterator3.next();
                String method = (String) map.get("method");
                if(method==null){
                    break;
                }
                String lowerCase = method.toLowerCase();
                if (lowerCase.endsWith(next1)){
                    b=true;
                    break;
                }
            }
            if(a&&b&&!next.contains("disconnect")){
                results.add(next);
            }
        }
        HashSet<String> res = new HashSet<>();
        Random rand = new Random();
        int size = results.size();
        if(size>bound){
            int i=0;
            while (i<bound){
                res.add(results.get(rand.nextInt(size)));
                i++;
            }
        }
        res.add("<java.net.URLConnection: void connect()>");
        res.add("<java.net.URL: java.net.URLConnection openConnection()>");
        res.add("<okhttp3.HttpUrl: okhttp3.HttpUrl get(java.net.URL)>");
        res.add("<okhttp3.HttpUrl: okhttp3.HttpUrl get(java.net.URI)>");
        res.add("<java.net.Socket: void connect(java.net.SocketAddress,int)>");
        ArrayList<String> re = new ArrayList<>();
        re.addAll(res);
        return re;
    }
    public static Set<String> broadcastMethodSig(){
        Set<String> broadcast= new HashSet<>();
        broadcast.add("<android.app.Activity: void sendBroadcast(android.content.Intent)>");
        broadcast.add("<android.app.Activity: void sendBroadcast(android.content.Intent,java.lang.String)>");
        broadcast.add("<android.app.Activity: void sendBroadcastAsUser(android.content.Intent,android.os.UserHandle)>");
        broadcast.add("<android.app.Activity: void sendBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String)>");
        broadcast.add("<android.app.Activity: void sendOrderedBroadcast(android.content.Intent,java.lang.String,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)>");
        broadcast.add("<android.app.Activity: void sendOrderedBroadcast(android.content.Intent,java.lang.String)>");
        broadcast.add("<android.app.Activity: void sendOrderedBroadcastAsUser(android.content.Intent,android.os.UserHandle,java.lang.String,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)>");
        broadcast.add("<android.app.Activity: void sendStickyBroadcast(android.content.Intent)>");
        broadcast.add("<android.app.Activity: void sendStickyBroadcastAsUser(android.content.Intent,android.os.UserHandle)>");
        broadcast.add("<android.app.Activity: void sendStickyOrderedBroadcast(android.content.Intent,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)>");
        broadcast.add("<android.app.Activity: void sendStickyOrderedBroadcastAsUser(android.content.Intent,android.os.UserHandle,android.content.BroadcastReceiver,android.os.Handler,int,java.lang.String,android.os.Bundle)>");
        broadcast.add("<android.app.Activity: void sendBroadcastWithMultiplePermissions(android.content.Intent,java.lang.String[])>");
        Iterator<String> iterator = broadcast.iterator();
        Set<String> newSet = new HashSet<>();
        while (iterator.hasNext()){
            String next = iterator.next();
            newSet.add(next.replace("android.app.Activity","android.content.Context"));
        }
        broadcast.addAll(newSet);
        return broadcast;
    }
    public static List<Map> findDataIntoFilePlus(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        //"RandomAccessFile" 尚未实现
        ArrayList<Map> results = new ArrayList<>();
        List<List> pathes = Util.getPathes("<java.io.FileOutputStream: void <init>(java.lang.String)>",nodes,nodeReverse,parents_info);
        pathes.addAll(Util.getPathes("<java.io.FileOutputStream: void <init>(java.lang.String,boolean)>",nodes,nodeReverse,parents_info));
        pathes.addAll(Util.getPathes( "<android.content.ContextWrapper: java.io.FileOutputStream openFileOutput(java.lang.String,int)>",nodes,nodeReverse,parents_info));
        for(int i=0;i<pathes.size();i++){
            List chain=pathes.get(i);
            String parent = (String) chain.get(chain.size()-2);
            Body methodBody = Util.getMethodBody(parent);
            UnitPatchingChain bodyUnits = methodBody.getUnits();
            Iterator<Unit> unitIterator = bodyUnits.iterator();
            while (unitIterator.hasNext()){
                Unit next = unitIterator.next();
                if(next instanceof JInvokeStmt){
                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                    String methodRef = invokeExpr.getMethodRef().toString();
                    if(methodRef.equals("<java.io.FileOutputStream: void <init>(java.lang.String)>")||methodRef.equals("<java.io.FileOutputStream: void <init>(java.lang.String,boolean)>")){
                        Value arg = invokeExpr.getArg(0);
                        String argStr = arg.toString();
                        Map<String, Object> map = new HashMap<>();
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
        List<List> pathes1 = Util.getPathes("<java.io.FileOutputStream: void <init>(java.io.File)>",nodes,nodeReverse,parents_info);
        pathes1.addAll(Util.getPathes("<java.io.FileOutputStream: void <init>(java.io.File,boolean)>",nodes,nodeReverse,parents_info));
        for(int i=0;i<pathes1.size();i++){
            List chain=pathes1.get(i);
            String parent = (String) chain.get(chain.size()-2);
            Body methodBody = Util.getMethodBody(parent);
            UnitPatchingChain bodyUnits = methodBody.getUnits();
            Iterator<Unit> unitIterator = bodyUnits.iterator();
            ArrayList<Unit> unitArrayList = new ArrayList<>();
            while (unitIterator.hasNext()){
                unitArrayList.add(unitIterator.next());
            }
            for(int j=0;j<unitArrayList.size();j++){
                Unit next = unitArrayList.get(j);
                if(next instanceof JInvokeStmt){
                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                    String methodRef = invokeExpr.getMethodRef().toString();
                    if(methodRef.equals("<java.io.FileOutputStream: void <init>(java.io.File)>")||methodRef.equals("<java.io.FileOutputStream: void <init>(java.io.File,boolean)>")){
                        for(int n=j-1;n>0;n--){
                            Unit last = unitArrayList.get(n);
                            if(last instanceof JInvokeStmt){
                                InvokeStmt jInvokeStmt1 = (JInvokeStmt) last;
                                InvokeExpr invokeExpr1 = jInvokeStmt1.getInvokeExpr();
                                String className = invokeExpr1.getMethod().getClass().getName();
                                if(className.equals("java.io.File")){
                                    String methodMame = invokeExpr1.getMethodRef().getName();{
                                        if(methodMame.equals("<init>")){
                                            Value arg = invokeExpr.getArg(0);
                                            String argStr = arg.toString();
                                            Map<String, Object> map = new HashMap<>();
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
                        }
                    }
                }
            }
        }
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
    public static List<Map> findDataIntoDBPlus(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
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

        List<String> replaceApi = new ArrayList<>();
        replaceApi.add("<android.database.sqlite.SQLiteDatabase: long replace(java.lang.String,java.lang.String,android.content.ContentValues)>");
        replaceApi.add("<android.database.sqlite.SQLiteDatabase: long replaceOrThrow(java.lang.String,java.lang.String,android.content.ContentValues)>");
        List<List> replacePathes = new ArrayList<>();
        for(String api: replaceApi){
            replacePathes.addAll(Util.getPathes(api,nodes,nodeReverse,parents_info));
        }
        for(List chain :replacePathes){
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
                    if(replaceApi.contains(methodRef)){
                        Value arg = invokeExpr.getArg(0);
                        String argStr = arg.toString();
                        Map<String, Object> map = new HashMap<>();
                        map.put("type","replace");
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

        List<String> updateApi = new ArrayList<>();
        updateApi.add("<android.database.sqlite.SQLiteDatabase: int update(java.lang.String,android.content.ContentValues,java.lang.String,java.lang.String[])>");
        updateApi.add("<android.database.sqlite.SQLiteDatabase: int updateWithOnConflict(java.lang.String,android.content.ContentValues,java.lang.String,java.lang.String[],int)>");
        List<List> updatePathes = new ArrayList<>();
        for(String api : updateApi){
            updatePathes.addAll(Util.getPathes(api,nodes,nodeReverse,parents_info));
        }
        for(List chain:updatePathes){
            String parent=(String) chain.get(chain.size()-2);
            Body methodBody = Util.getMethodBody(parent);
            UnitPatchingChain bodyUnits = methodBody.getUnits();
            Iterator<Unit> unitIterator = bodyUnits.iterator();
            while (unitIterator.hasNext()){
                Unit next = unitIterator.next();
                if(next instanceof JInvokeStmt){
                    JInvokeStmt jInvokeStmt = (JInvokeStmt) next;
                    InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                    String methodRef = invokeExpr.getMethodRef().toString();
                    if(updateApi.contains(methodRef)){
                        Value arg = invokeExpr.getArg(0);
                        String argStr = arg.toString();
                        Map<String, Object> map = new HashMap<>();
                        map.put("type","update");
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
//                    String source="";
//                    for(int n=0;n<list.size();n++){
//                        source=source+Util.getMethodBody(list.get(0).toString());
//                    }
                    //设计方法规则找到data,url
                    Map<String, Object> map = new HashMap<>();
                    map.put("api",api);
                    map.put("target","");
                    map.put("invoke_chain", list);
                    //携带数据待补充
//                    String data = "";
//                    map.put("data", data);
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
        results.add("<javax.crypto.Cipher: int doFinal(java.nio.ByteBuffer,java.nio.ByteBuffer)>");
        results.add("<javax.crypto.Cipher: byte[] doFinal(byte[],int,int)>");
        results.add("<java.security.Signature: java.security.Signature getInstance(java.lang.String)>");
//        Set<String> classSet=new HashSet<>();
//        Set<String> actionSet=new HashSet<>();
//        classSet.add("md5");classSet.add("rsa");
//        classSet.add("aes");classSet.add("base64");
//        classSet.add("encrypt");
//        actionSet.add("encode");actionSet.add("encrypt");
//
//        Iterator<String> iterator = nodes.keySet().iterator();
//        Map<String,Map> methodMap=new HashMap();
//        while (iterator.hasNext()){
//            String next = iterator.next();
//           try {
//               SootMethod method = Scene.v().grabMethod(next);
//               Map<String,String> map=new HashMap<>();
//               map.put("class",method.getDeclaringClass().getShortName());
//               map.put("method",method.getName());
//               methodMap.put(method.getSignature(),map);
//           }catch (Exception e){
//               continue;
//           }
//        }
//        Iterator<String> iterator1 = methodMap.keySet().iterator();
//        while (iterator1.hasNext()){
//            boolean a=false,b=false;
//            String next = iterator1.next();
//            Map map = methodMap.get(next);
//            Iterator<String> iterator2 = classSet.iterator();
//            while (iterator2.hasNext()){
//                String next1 = iterator2.next();
//                String aClass = (String) map.get("class");
//                if(aClass==null){
//                    break;
//                }
//                if(aClass.toLowerCase().contains(next1)){
//                    a=true;
//                    break;
//                }
//            }
//            Iterator<String> iterator3 = actionSet.iterator();
//            while (iterator3.hasNext()){
//                String next1 = iterator3.next();
//                String method = (String) map.get("method");
//                if(method==null){
//                    break;
//                }
//                String lowerCase = method.toLowerCase();
//                if (lowerCase.endsWith(next1)){
//                    b=true;
//                    break;
//                }
//            }
//            if(a&&b){
//                results.add(next);
//            }
//        }
        return results;
    }
}
