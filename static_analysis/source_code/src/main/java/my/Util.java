package my;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonWriter;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.manifest.IComponentContainer;
import soot.jimple.infoflow.android.manifest.binary.BinaryManifestActivity;
import soot.jimple.internal.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.Chain;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * @description: 工具类（json数据生成功能，反编译功能）
 * @author: xxx
 * @date: 2022/9/22 15:05
 **/
public class Util {

    public static String writeMapToJson(String jsonPath, Map inMap, boolean flag) throws UnsupportedEncodingException{
        /**
         * 将MAP数据写入json文件
         * @param jsonPath json文件路径
         * @param inMap Map类型数据
         * @param flag 写入状态，true表示在文件中追加数据，false表示覆盖文件数据
         * @return 写入文件状态  成功或失败
         */
        // Map数据转化为Json，再转换为String

//        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
//        String s1 = gson.toJson(inMap);
//        File jsonFile = new File(jsonPath);
//        try {
//            // 文件不存在就创建文件
//            if (!jsonFile.exists()) {
//                jsonFile.createNewFile();
//            }
//            FileWriter fileWriter = new FileWriter(jsonFile.getAbsoluteFile(), flag);
//            BufferedWriter bw = new BufferedWriter(fileWriter);
//            bw.write(s1);
//            bw.close();
//            return "success";
//        } catch (IOException e) {
//            return "error";
//        }
        try {
            // 创建ObjectMapper对象
            ObjectMapper objectMapper = new ObjectMapper();

            // 将Map写入JSON文件
            objectMapper.writeValue(new File(jsonPath), inMap);

            System.out.println("Map已成功写入JSON文件: " + jsonPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }
    public static Boolean writeListToJson(String jsonPath, List<Map> list, boolean b) {
        /**
         * 将list数据写入json文件
         * @param jsonPath json文件路径
         * @param inMap Map类型数据
         * @param flag 写入状态，true表示在文件中追加数据，false表示覆盖文件数据
         * @return 写入文件状态  成功或失败
         */
        try {
            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            JsonWriter jsonWriter = new JsonWriter(new FileWriter(jsonPath,b));
            gson.toJson(list,List.class , jsonWriter);
            jsonWriter.close();
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
//        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
//        String s1 = gson.toJson(list);
//        File jsonFile = new File(jsonPath);
//        try {
//            // 文件不存在就创建文件
//            if (!jsonFile.exists()) {
//                jsonFile.createNewFile();
//            }
//            FileWriter fileWriter = new FileWriter(jsonFile.getAbsoluteFile(), b);
//            BufferedWriter bw = new BufferedWriter(fileWriter);
//            bw.write(s1);
//            bw.close();
//            return true;
//        } catch (IOException e) {
//            return false;
//        }
    }
    public static Boolean writeListToJson1(String jsonPath, List<String> list, boolean b) {
        /**
         * 将list数据写入json文件
         * @param jsonPath json文件路径
         * @param inMap Map类型数据
         * @param flag 写入状态，true表示在文件中追加数据，false表示覆盖文件数据
         * @return 写入文件状态  成功或失败
         */
        try {
            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            JsonWriter jsonWriter = new JsonWriter(new FileWriter(jsonPath,b));
            gson.toJson(list,List.class , jsonWriter);
            jsonWriter.close();
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
//        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
//        String s1 = gson.toJson(list);
//        File jsonFile = new File(jsonPath);
//        try {
//            // 文件不存在就创建文件
//            if (!jsonFile.exists()) {
//                jsonFile.createNewFile();
//            }
//            FileWriter fileWriter = new FileWriter(jsonFile.getAbsoluteFile(), b);
//            BufferedWriter bw = new BufferedWriter(fileWriter);
//            bw.write(s1);
//            bw.close();
//            return true;
//        } catch (IOException e) {
//            return false;
//        }
    }
    public static Boolean writeListToJson2(String jsonPath, List<List> list, boolean b) {
        /**
         * 将list数据写入json文件
         * @param jsonPath json文件路径
         * @param inMap Map类型数据
         * @param flag 写入状态，true表示在文件中追加数据，false表示覆盖文件数据
         * @return 写入文件状态  成功或失败
         */
        try {
            Gson gson = new GsonBuilder().disableHtmlEscaping().create();
            JsonWriter jsonWriter = new JsonWriter(new FileWriter(jsonPath,b));
            gson.toJson(list,List.class , jsonWriter);
            jsonWriter.close();
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
//        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
//        String s1 = gson.toJson(list);
//        File jsonFile = new File(jsonPath);
//        try {
//            // 文件不存在就创建文件
//            if (!jsonFile.exists()) {
//                jsonFile.createNewFile();
//            }
//            FileWriter fileWriter = new FileWriter(jsonFile.getAbsoluteFile(), b);
//            BufferedWriter bw = new BufferedWriter(fileWriter);
//            bw.write(s1);
//            bw.close();
//            return true;
//        } catch (IOException e) {
//            return false;
//        }
    }
    public static String getMainPackage(String path){
        /**
         * @description: 拿到apk的主包信息
         * @author: xxx
         * @date: 2022/9/27 10:53
         * @param: path 反编译结果文件保存的根目录
         * @return: String 主包
         **/
        String filePath = path + "\\resources\\AndroidManifest.xml";
        File file = new File(filePath);
        if(file.isFile()){
            try {
                DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                Document document = documentBuilder.parse(filePath);
                NodeList manifest = document.getElementsByTagName("manifest");
                Node aPackage = manifest.item(0).getAttributes().getNamedItem("package");
                return aPackage.getNodeValue();
            } catch (ParserConfigurationException | SAXException | IOException e) {
                e.printStackTrace();
            }


        }
        return null;

    }
    public static Map<String, Object> callGraphGenerate(Chain<SootClass> applicationClasses,String outPut) throws IOException {
        /**
         * @description: 生成函数调用图,并维护一张查询表
         * @author: xxx
         * @date: 2022/9/28 11:30
         * @param: applicationClasses apk包含类
         * @param: cg 目标调用图存储容器
         * @return: void
         **/
        Map<String,Object> cg =new HashMap<>();
        Map<String,Long> nodes=new HashMap<>();
        Map<Long,String> nodesReverse=new HashMap<>();
        Map<Long,List> parentsInfo=new HashMap<>();

        Iterator<SootClass> iterator = applicationClasses.iterator();
        long id=0;
        while (iterator.hasNext()){
            SootClass sootClass = iterator.next();
            List<SootMethod> methods = sootClass.getMethods();
            for(int j=0;j<methods.size();j++){
                SootMethod method = methods.get(j);
                Body activeBody = null;
                try {
                    activeBody = method.retrieveActiveBody();
                }catch (Exception e){
                    continue;
                }
                String parent = method.getSignature();
                long parentId=-1;
                if(nodes.keySet().contains(parent)){
                    parentId=nodes.get(parent);
                }else {
                    nodes.put(parent,id);
                    nodesReverse.put(id,parent);
                    parentId=id;
                    id=id+1;
                }
                UnitPatchingChain units = activeBody.getUnits();
                Iterator<Unit> iterator1 = units.iterator();
                while (iterator1.hasNext()){
                    try {
                        Unit next = iterator1.next();
                        String simpleName = next.getClass().getSimpleName();
                        if(simpleName.equals("JInvokeStmt")){
                            JInvokeStmt next1 = (JInvokeStmt) next;
                            SootMethod method1 = next1.getInvokeExpr().getMethod();
                            String child = method1.getSignature();
                            long childId=-1;
                            if(nodes.keySet().contains(child)){
                                childId=nodes.get(child);
                            }else {
                                nodes.put(child,id);
                                nodesReverse.put(id,child);
                                childId=id;
                                id=id+1;
                            }
                            if(parentsInfo.keySet().contains(childId)){
                                parentsInfo.get(childId).add(parentId);
                            }else {
                                ArrayList<Long> parentsList = new ArrayList<>();
                                parentsList.add(parentId);
                                parentsInfo.put(childId,parentsList);
                            }
                            //时间周期函数绑定
                            if(method1.getName().equals("<init>")){
                                Chain<SootClass> interfaces = method1.getDeclaringClass().getInterfaces();
                                if(interfaces.size()>0){
                                    boolean listener=false;
                                    Iterator<SootClass> iterator2 = interfaces.iterator();
                                    while (iterator2.hasNext()){
                                        SootClass next2 = iterator2.next();
                                        if(next2.getPackageName().equals("android.view")){
                                            listener=true;
                                            break;
                                        }
                                    }
                                    if (listener){
                                        List<SootMethod> methods1 = method1.getDeclaringClass().getMethods();
                                        for(SootMethod method3:methods1){
                                            String childListener = method3.getSignature();
                                            long childIdListener=-1;
                                            if(nodes.keySet().contains(childListener)){
                                                childIdListener=nodes.get(childListener);
                                            }else {
                                                nodes.put(childListener,id);
                                                nodesReverse.put(id,childListener);
                                                childIdListener=id;
                                                id=id+1;
                                            }
                                            if(parentsInfo.keySet().contains(childIdListener)){
                                                parentsInfo.get(childIdListener).add(parentId);
                                            }else {
                                                ArrayList<Long> parentsList = new ArrayList<>();
                                                parentsList.add(parentId);
                                                parentsInfo.put(childIdListener,parentsList);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if(simpleName.equals("JAssignStmt")){
                            JAssignStmt next1 = (JAssignStmt) next;
                            Value rightOp = next1.getRightOp();
                            String simpleName1 = rightOp.getClass().getSimpleName();
                            if(simpleName1.equals("JVirtualInvokeExpr")||simpleName1.equals("JStaticInvokeExpr")||simpleName1.equals("JSpecialInvokeExpr")||simpleName1.equals("JDynamicInvokeExpr")||simpleName1.equals("JInterfaceInvokeExpr")){
                                AbstractInvokeExpr rightOp1 = (AbstractInvokeExpr) rightOp;
                                SootMethod method1 = Scene.v().grabMethod(rightOp1.getMethodRef().getSignature());
                                String child = method1.getSignature();
                                long childId=-1;
                                if(nodes.keySet().contains(child)){
                                    childId=nodes.get(child);
                                }else {
                                    nodes.put(child,id);
                                    nodesReverse.put(id,child);
                                    childId=id;
                                    id=id+1;
                                }
                                if(parentsInfo.keySet().contains(childId)){
                                    parentsInfo.get(childId).add(parentId);
                                }else {
                                    ArrayList<Long> parentsList = new ArrayList<>();
                                    parentsList.add(parentId);
                                    parentsInfo.put(childId,parentsList);
                                }
                            }else if(simpleName1.equals("JNewExpr")){
                                JNewExpr rightOp1 = (JNewExpr) rightOp;
                                Type type = rightOp1.getType();
                                if(type instanceof RefType){
                                    SootClass sootClass1 =((RefType)type).getSootClass();
                                    SootClass first = sootClass1.getInterfaces().getFirst();
                                    if(first.getName().equals("java.lang.Runnable")){
                                        SootMethod method2 = sootClass1.getMethod("void run()");
                                        String child = method2.getSignature();
                                        long childId=-1;
                                        if(nodes.keySet().contains(child)){
                                            childId=nodes.get(child);
                                        }else {
                                            nodes.put(child,id);
                                            nodesReverse.put(id,child);
                                            childId=id;
                                            id=id+1;
                                        }
                                        if(parentsInfo.keySet().contains(childId)){
                                            parentsInfo.get(childId).add(parentId);
                                        }else {
                                            ArrayList<Long> parentsList = new ArrayList<>();
                                            parentsList.add(parentId);
                                            parentsInfo.put(childId,parentsList);
                                        }
                                    }
                                }
                            }
                        }
                    }catch (Exception e){
                        continue;
                    }
                }

            }
        }
        Map<Long,List> newParentsInfo=new HashMap<>();
        for(Long key :parentsInfo.keySet()){
            List list = parentsInfo.get(key);
            list= (List) list.stream().distinct().collect(Collectors.toList());
            newParentsInfo.put(key,list);
        }
//        mixDynamicCg(nodes,nodesReverse,newParentsInfo,dynamicCgJson);
        //反射
//        Map<String,Set> nodesMap=new HashMap<>();
//        for(String key:nodes.keySet()){
//            String[] keyList = key.split(" ");
//            String packageName = keyList[0].substring(1, keyList[0].length() - 1);
//            String method = keyList[2].split("\\(")[0];
//            String newKey=packageName+"."+method;
//            if(nodesMap.containsKey(newKey)){
//                Set set = nodesMap.get(newKey);
//                set.add(key);
//            }else {
//                HashSet<Object> tmpSet = new HashSet<>();
//                tmpSet.add(key);
//                nodesMap.put(newKey,tmpSet);
//            }
//        }
//
//        List<Long> parents = getParents("<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>", nodes, newParentsInfo);
//        List<String> methodList=new ArrayList<>();
//        for(long parent:parents){
//            String parentSig = nodesReverse.get(parent);
//            Body methodBody = getMethodBody(parentSig);
//            Iterator<Unit> iterator1 = methodBody.getUnits().iterator();
//            List<Unit> unitList=new ArrayList<>();
//            while (iterator1.hasNext()){
//                Unit next = iterator1.next();
//                unitList.add(next);
//            }
//            for(int i=0;i<unitList.size();i++){
//                Unit unit = unitList.get(i);
//                if(unit instanceof JAssignStmt){
//                    JAssignStmt next1 = (JAssignStmt) unit;
//                    Value rightOp = next1.getRightOp();
//                    if(rightOp instanceof ClassConstant){
//                        String cpackage=((ClassConstant) rightOp).getValue();
//                        cpackage=cpackage.substring(1,cpackage.length()-1);
//                        cpackage=cpackage.replace("/",".");
//                        for(int j=i;j<unitList.size();j++){
//                            Unit unit1 = unitList.get(j);
//                            if(unit1 instanceof JAssignStmt){
//                                JAssignStmt unit11 = (JAssignStmt) unit1;
//                                Value rightOp1 = unit11.getRightOp();
//                                if(rightOp1.toString().contains("<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>")){
//                                    JVirtualInvokeExpr rightOp11 = (JVirtualInvokeExpr) rightOp1;
//                                    Value value = rightOp11.getArgs().get(0);
//                                    String s = value.toString();
//                                    s=s.substring(1,s.length()-1);
//                                    System.out.println(s);
//                                    methodList.add(cpackage+"."+s);
//                                    break;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//        long id1=-1;
//        if(nodes.keySet().contains("<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>")){
//            id1=nodes.get("<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>");
//        }else {
//            id1=nodes.size();
//            nodes.put("<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>",id1);
//        }
//        for(String sig :methodList){
//            Set<String> set = nodesMap.get(sig);
//            if(set!=null){
//                for(String realSig:set){
//                    long childId=nodes.get(realSig);
//                    if (newParentsInfo.keySet().contains(childId)){
//                        newParentsInfo.get(childId).add(id1);
//                    }else {
//                        ArrayList<Long> longs = new ArrayList<Long>();
//                        longs.add(id1);
//                        newParentsInfo.put(childId,longs);
//                    }
//                }
//            }else {
//                int size = nodes.size();
//                nodes.put(sig, (long) size);
//                nodesReverse.put((long) size,sig);
//                ArrayList<Long> longs = new ArrayList<Long>();
//                longs.add(id1);
//                newParentsInfo.put((long) size,longs);
//            }
//        }

        cg.put("nodes",nodes);
        cg.put("node_reverse",nodesReverse);
        cg.put("parents_info",newParentsInfo);
        writeMapToJson(new File(outPut,"cg.json").getAbsolutePath(),cg,false);
        return cg;
    }
    public static Map<String, Object> callGraphGenerate(Chain<SootClass> applicationClasses, CallGraph callGraph, String outPut) throws IOException {
        /**
         * @description: 生成函数调用图,并维护一张查询表
         * @author: xxx
         * @date: 2022/9/28 11:30
         * @param: applicationClasses apk包含类
         * @param: cg 目标调用图存储容器
         * @return: void
         **/
        HashSet<String> lifeCycle = getLifeCycleMethodSig();
        Map<String,Object> cg =new HashMap<>();
        Map<String,Long> nodes=new HashMap<>();
        Map<Long,String> nodesReverse=new HashMap<>();
        Map<Long, List> parentsInfo=new HashMap<>();
        Map<Long, List> childrenInfo=new HashMap<>();

        Iterator<SootClass> iterator = applicationClasses.iterator();
        long id=0;
        while (iterator.hasNext()){
            SootClass sootClass = iterator.next();
            List<SootMethod> methods = sootClass.getMethods();
            //生命周期
            Map<String,List> attributes = new HashMap<>();
            for(int j=0;j<methods.size();j++){
                SootMethod sootMethod = methods.get(j);
                String methodName = sootMethod.getName();
                if(lifeCycle.contains(methodName)){
                    Body activeBody = null;
                    try {
                        activeBody = sootMethod.retrieveActiveBody();
                    }catch (Exception e){
                        continue;
                    }
                    Iterator<Unit> iterator1 = activeBody.getUnits().iterator();
                    while (iterator1.hasNext()){
                        Unit next = iterator1.next();
                        if(next instanceof JAssignStmt){
                            JAssignStmt next1 = (JAssignStmt) next;
                            Value leftOp = next1.getLeftOp();
                            if(leftOp instanceof JInstanceFieldRef){
                                JInstanceFieldRef leftOp1 = (JInstanceFieldRef) leftOp;
                                SootFieldRef fieldRef = leftOp1.getFieldRef();
                                String signature = fieldRef.getSignature();
                                if(attributes.containsKey(signature)){
                                    attributes.get(signature).add(sootMethod.getSignature());
                                }else {
                                    ArrayList<String> cycles = new ArrayList<>();
                                    cycles.add(sootMethod.getSignature());
                                    attributes.put(signature,cycles);
                                }
                            }
                        }
                    }
                }
            }
            for(int j=0;j<methods.size();j++){
                SootMethod method = methods.get(j);
                Body activeBody = null;
                try {
                    activeBody = method.retrieveActiveBody();
                }catch (Exception e){
                    continue;
                }
                String parent = method.getSignature();
                long parentId=-1;
                if(nodes.keySet().contains(parent)){
                    parentId=nodes.get(parent);
                }else {
                    nodes.put(parent,id);
                    nodesReverse.put(id,parent);
                    parentId=id;
                    id=id+1;
                }
                UnitPatchingChain units = activeBody.getUnits();
                Iterator<Unit> iterator1 = units.iterator();
                while (iterator1.hasNext()){
                    try {
                        Unit next = iterator1.next();
                        String simpleName = next.getClass().getSimpleName();
                        if(simpleName.equals("JInvokeStmt")){
                            JInvokeStmt next1 = (JInvokeStmt) next;
                            SootMethod method1 = next1.getInvokeExpr().getMethod();
                            try {
                                Edge edge = new Edge(method, (Stmt) next,method1);
                                callGraph.addEdge(edge);
                            }catch (Exception e){
//                                e.printStackTrace();
                            }
                            String child = method1.getSignature();
                            long childId=-1;
                            if(nodes.keySet().contains(child)){
                                childId=nodes.get(child);
                            }else {
                                nodes.put(child,id);
                                nodesReverse.put(id,child);
                                childId=id;
                                id=id+1;
                            }
                            if(parentsInfo.keySet().contains(childId)){
                                parentsInfo.get(childId).add(parentId);
                            }else {
                                ArrayList<Long> parentsList = new ArrayList<>();
                                parentsList.add(parentId);
                                parentsInfo.put(childId,parentsList);
                            }
                            if(childrenInfo.keySet().contains(parentId)){
                                childrenInfo.get(parentId).add(childId);
                            }else {
                                ArrayList<Long> childrenList = new ArrayList<>();
                                childrenList.add(childId);
                                childrenInfo.put(parentId,childrenList);
                            }
                            //时间周期函数绑定
                            if(method1.getName().equals("<init>")){
                                Chain<SootClass> interfaces = method1.getDeclaringClass().getInterfaces();
                                if(interfaces.size()>0){
                                    boolean listener=false;
                                    Iterator<SootClass> iterator2 = interfaces.iterator();
                                    while (iterator2.hasNext()){
                                        SootClass next2 = iterator2.next();
                                        if(next2.getPackageName().equals("android.view")){
                                            listener=true;
                                            break;
                                        }
                                    }
                                    if (listener){
                                        List<SootMethod> methods1 = method1.getDeclaringClass().getMethods();
                                        for(SootMethod method3:methods1){

                                            try {
                                                Edge edge = new Edge(method, (Stmt) next,method3);
                                                callGraph.addEdge(edge);
                                            }catch (Exception e){
//                                                e.printStackTrace();
                                            }

                                            String childListener = method3.getSignature();
                                            long childIdListener=-1;
                                            if(nodes.keySet().contains(childListener)){
                                                childIdListener=nodes.get(childListener);
                                            }else {
                                                nodes.put(childListener,id);
                                                nodesReverse.put(id,childListener);
                                                childIdListener=id;
                                                id=id+1;
                                            }
                                            if(parentsInfo.keySet().contains(childIdListener)){
                                                parentsInfo.get(childIdListener).add(parentId);
                                            }else {
                                                ArrayList<Long> parentsList = new ArrayList<>();
                                                parentsList.add(parentId);
                                                parentsInfo.put(childIdListener,parentsList);
                                            }
                                            if(childrenInfo.keySet().contains(parentId)){
                                                childrenInfo.get(parentId).add(childId);
                                            }else {
                                                ArrayList<Long> childrenList = new ArrayList<>();
                                                childrenList.add(childId);
                                                childrenInfo.put(parentId,childrenList);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if(simpleName.equals("JAssignStmt")){
                            JAssignStmt next1 = (JAssignStmt) next;
                            Value rightOp = next1.getRightOp();
                            String simpleName1 = rightOp.getClass().getSimpleName();
                            if(simpleName1.equals("JVirtualInvokeExpr")||simpleName1.equals("JStaticInvokeExpr")||simpleName1.equals("JSpecialInvokeExpr")||simpleName1.equals("JDynamicInvokeExpr")||simpleName1.equals("JInterfaceInvokeExpr")){
                                AbstractInvokeExpr rightOp1 = (AbstractInvokeExpr) rightOp;
                                String child = rightOp1.getMethodRef().getSignature();
                                SootMethod method1 = Scene.v().grabMethod(child);

                                try {
                                    Edge edge = new Edge(method, (Stmt) next,method1);
                                    callGraph.addEdge(edge);
                                }catch (Exception e){
//                                    e.printStackTrace();
                                }

                                long childId=-1;
                                if(nodes.keySet().contains(child)){
                                    childId=nodes.get(child);
                                }else {
                                    nodes.put(child,id);
                                    nodesReverse.put(id,child);
                                    childId=id;
                                    id=id+1;
                                }
                                if(parentsInfo.keySet().contains(childId)){
                                    parentsInfo.get(childId).add(parentId);
                                }else {
                                    ArrayList<Long> parentsList = new ArrayList<>();
                                    parentsList.add(parentId);
                                    parentsInfo.put(childId,parentsList);
                                }
                                if(childrenInfo.keySet().contains(parentId)){
                                    childrenInfo.get(parentId).add(childId);
                                }else {
                                    ArrayList<Long> childrenList = new ArrayList<>();
                                    childrenList.add(childId);
                                    childrenInfo.put(parentId,childrenList);
                                }
                            }
                            else if(simpleName1.equals("JNewExpr")){
                                JNewExpr rightOp1 = (JNewExpr) rightOp;
                                Type type = rightOp1.getType();
                                if(type instanceof RefType){
                                    SootClass sootClass1 =((RefType)type).getSootClass();
                                    SootClass first = sootClass1.getInterfaces().getFirst();
                                    if(first.getName().equals("java.lang.Runnable")){
                                        SootMethod method2 = sootClass1.getMethod("void run()");

                                        try {
                                            Edge edge = new Edge(method, (Stmt) next,method2);
                                            callGraph.addEdge(edge);
                                        }catch (Exception e){
//                                            e.printStackTrace();
                                        }

                                        String child = method2.getSignature();
                                        long childId=-1;
                                        if(nodes.keySet().contains(child)){
                                            childId=nodes.get(child);
                                        }else {
                                            nodes.put(child,id);
                                            nodesReverse.put(id,child);
                                            childId=id;
                                            id=id+1;
                                        }
                                        if(parentsInfo.keySet().contains(childId)){
                                            parentsInfo.get(childId).add(parentId);
                                        }else {
                                            ArrayList<Long> parentsList = new ArrayList<>();
                                            parentsList.add(parentId);
                                            parentsInfo.put(childId,parentsList);
                                        }
                                        if(childrenInfo.keySet().contains(parentId)){
                                            childrenInfo.get(parentId).add(childId);
                                        }else {
                                            ArrayList<Long> childrenList = new ArrayList<>();
                                            childrenList.add(childId);
                                            childrenInfo.put(parentId,childrenList);
                                        }
                                    }
                                }
                            }
                            //生命周期
                            else if(rightOp instanceof JInstanceFieldRef){
                                JInstanceFieldRef rightOp1 = (JInstanceFieldRef) rightOp;
                                String signature = rightOp1.getFieldRef().getSignature();
                                List<String> list = attributes.get(signature);
                                for(String cycleParent:list){
                                    SootMethod method1 = Scene.v().getMethod(cycleParent);
                                    try {
                                        Edge edge = new Edge(method1, (Stmt) next,method);
                                        callGraph.addEdge(edge);
                                    }catch (Exception e){
//                                        e.printStackTrace();
                                    }
                                    parentId=-1;
                                    if(nodes.keySet().contains(cycleParent)){
                                        parentId=nodes.get(cycleParent);
                                    }else {
                                        nodes.put(cycleParent,id);
                                        nodesReverse.put(id,cycleParent);
                                        parentId=id;
                                        id=id+1;
                                    }

                                    String child = method.getSignature();
                                    long childId=-1;
                                    if(nodes.keySet().contains(child)){
                                        childId=nodes.get(child);
                                    }else {
                                        nodes.put(child,id);
                                        nodesReverse.put(id,child);
                                        childId=id;
                                        id=id+1;
                                    }
                                    if(parentsInfo.keySet().contains(childId)){
                                        parentsInfo.get(childId).add(parentId);
                                    }else {
                                        ArrayList<Long> parentsList = new ArrayList<>();
                                        parentsList.add(parentId);
                                        parentsInfo.put(childId,parentsList);
                                    }
                                    if(childrenInfo.keySet().contains(parentId)){
                                        childrenInfo.get(parentId).add(childId);
                                    }else {
                                        ArrayList<Long> childrenList = new ArrayList<>();
                                        childrenList.add(childId);
                                        childrenInfo.put(parentId,childrenList);
                                    }
                                }
                            }
                        }
                    }catch (Exception e){
                        continue;
                    }
                }

            }
        }
        Map<Long,List> newParentsInfo=new HashMap<>();
        for(Long key :parentsInfo.keySet()){
            List list = parentsInfo.get(key);
            list= (List) list.stream().distinct().collect(Collectors.toList());
            newParentsInfo.put(key,list);
        }
        Map<Long,List> newChildrenInfo=new HashMap<>();
        for(Long key :childrenInfo.keySet()){
            List list = childrenInfo.get(key);
            list= (List) list.stream().distinct().collect(Collectors.toList());
            newChildrenInfo.put(key,list);
        }

        Scene.v().setCallGraph(callGraph);
        cg.put("nodes",nodes);
        cg.put("node_reverse",nodesReverse);
        cg.put("parents_info",newParentsInfo);
        cg.put("children_info",newChildrenInfo);
//        writeMapToJson(new File(outPut,"cg.json").getAbsolutePath(),cg,false);
        return cg;
    }
    public static Map<String, Object> callGraphGenerateWithReflection(Chain<SootClass> applicationClasses, CallGraph callGraph,String reflectionJson, String outPut) throws IOException {
        /**
         * @description: 生成函数调用图,并维护一张查询表
         * @author: xxx
         * @date: 2022/9/28 11:30
         * @param: applicationClasses apk包含类
         * @param: cg 目标调用图存储容器
         * @return: void
         **/
        HashSet<String> lifeCycle = getLifeCycleMethodSig();
        Map<String,Object> cg =new HashMap<>();
        Map<String,Long> nodes=new HashMap<>();
        Map<Long,String> nodesReverse=new HashMap<>();
        Map<Long, List> parentsInfo=new HashMap<>();

        Iterator<SootClass> iterator = applicationClasses.iterator();
        long id=0;
        while (iterator.hasNext()){
            SootClass sootClass = iterator.next();
            List<SootMethod> methods = sootClass.getMethods();
            //生命周期
            Map<String,List> attributes = new HashMap<>();
            for(int j=0;j<methods.size();j++){
                SootMethod sootMethod = methods.get(j);
                String methodName = sootMethod.getName();
                if(lifeCycle.contains(methodName)){
                    Body activeBody = null;
                    try {
                        activeBody = sootMethod.retrieveActiveBody();
                    }catch (Exception e){
                        continue;
                    }
                    Iterator<Unit> iterator1 = activeBody.getUnits().iterator();
                    while (iterator1.hasNext()){
                        Unit next = iterator1.next();
                        if(next instanceof JAssignStmt){
                            JAssignStmt next1 = (JAssignStmt) next;
                            Value leftOp = next1.getLeftOp();
                            if(leftOp instanceof JInstanceFieldRef){
                                JInstanceFieldRef leftOp1 = (JInstanceFieldRef) leftOp;
                                SootFieldRef fieldRef = leftOp1.getFieldRef();
                                String signature = fieldRef.getSignature();
                                if(attributes.containsKey(signature)){
                                    attributes.get(signature).add(sootMethod.getSignature());
                                }else {
                                    ArrayList<String> cycles = new ArrayList<>();
                                    cycles.add(sootMethod.getSignature());
                                    attributes.put(signature,cycles);
                                }
                            }
                        }
                    }
                }
            }
            for(int j=0;j<methods.size();j++){
                SootMethod method = methods.get(j);
                Body activeBody = null;
                try {
                    activeBody = method.retrieveActiveBody();
                }catch (Exception e){
                    continue;
                }
                String parent = method.getSignature();
                long parentId=-1;
                if(nodes.keySet().contains(parent)){
                    parentId=nodes.get(parent);
                }else {
                    nodes.put(parent,id);
                    nodesReverse.put(id,parent);
                    parentId=id;
                    id=id+1;
                }
                UnitPatchingChain units = activeBody.getUnits();
                Iterator<Unit> iterator1 = units.iterator();
                while (iterator1.hasNext()){
                    try {
                        Unit next = iterator1.next();
                        String simpleName = next.getClass().getSimpleName();
                        if(simpleName.equals("JInvokeStmt")){
                            JInvokeStmt next1 = (JInvokeStmt) next;
                            SootMethod method1 = next1.getInvokeExpr().getMethod();
                            try {
                                Edge edge = new Edge(method, (Stmt) next,method1);
                                callGraph.addEdge(edge);
                            }catch (Exception e){
//                                e.printStackTrace();
                            }

                            String child = method1.getSignature();
                            long childId=-1;
                            if(nodes.keySet().contains(child)){
                                childId=nodes.get(child);
                            }else {
                                nodes.put(child,id);
                                nodesReverse.put(id,child);
                                childId=id;
                                id=id+1;
                            }
                            if(parentsInfo.keySet().contains(childId)){
                                parentsInfo.get(childId).add(parentId);
                            }else {
                                ArrayList<Long> parentsList = new ArrayList<>();
                                parentsList.add(parentId);
                                parentsInfo.put(childId,parentsList);
                            }
                            //时间周期函数绑定
                            if(method1.getName().equals("<init>")){
                                Chain<SootClass> interfaces = method1.getDeclaringClass().getInterfaces();
                                if(interfaces.size()>0){
                                    boolean listener=false;
                                    Iterator<SootClass> iterator2 = interfaces.iterator();
                                    while (iterator2.hasNext()){
                                        SootClass next2 = iterator2.next();
                                        if(next2.getPackageName().equals("android.view")){
                                            listener=true;
                                            break;
                                        }
                                    }
                                    if (listener){
                                        List<SootMethod> methods1 = method1.getDeclaringClass().getMethods();
                                        for(SootMethod method3:methods1){

                                            try {
                                                Edge edge = new Edge(method, (Stmt) next,method3);
                                                callGraph.addEdge(edge);
                                            }catch (Exception e){
//                                                e.printStackTrace();
                                            }

                                            String childListener = method3.getSignature();
                                            long childIdListener=-1;
                                            if(nodes.keySet().contains(childListener)){
                                                childIdListener=nodes.get(childListener);
                                            }else {
                                                nodes.put(childListener,id);
                                                nodesReverse.put(id,childListener);
                                                childIdListener=id;
                                                id=id+1;
                                            }
                                            if(parentsInfo.keySet().contains(childIdListener)){
                                                parentsInfo.get(childIdListener).add(parentId);
                                            }else {
                                                ArrayList<Long> parentsList = new ArrayList<>();
                                                parentsList.add(parentId);
                                                parentsInfo.put(childIdListener,parentsList);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if(simpleName.equals("JAssignStmt")){
                            JAssignStmt next1 = (JAssignStmt) next;
                            Value rightOp = next1.getRightOp();
                            String simpleName1 = rightOp.getClass().getSimpleName();
                            if(simpleName1.equals("JVirtualInvokeExpr")||simpleName1.equals("JStaticInvokeExpr")||simpleName1.equals("JSpecialInvokeExpr")||simpleName1.equals("JDynamicInvokeExpr")||simpleName1.equals("JInterfaceInvokeExpr")){
                                AbstractInvokeExpr rightOp1 = (AbstractInvokeExpr) rightOp;
                                String child = rightOp1.getMethodRef().getSignature();
                                SootMethod method1 = Scene.v().grabMethod(child);

                                try {
                                    Edge edge = new Edge(method, (Stmt) next,method1);
                                    callGraph.addEdge(edge);
                                }catch (Exception e){
//                                    e.printStackTrace();
                                }

                                long childId=-1;
                                if(nodes.keySet().contains(child)){
                                    childId=nodes.get(child);
                                }else {
                                    nodes.put(child,id);
                                    nodesReverse.put(id,child);
                                    childId=id;
                                    id=id+1;
                                }
                                if(parentsInfo.keySet().contains(childId)){
                                    parentsInfo.get(childId).add(parentId);
                                }else {
                                    ArrayList<Long> parentsList = new ArrayList<>();
                                    parentsList.add(parentId);
                                    parentsInfo.put(childId,parentsList);
                                }
                            }
                            else if(simpleName1.equals("JNewExpr")){
                                JNewExpr rightOp1 = (JNewExpr) rightOp;
                                Type type = rightOp1.getType();
                                if(type instanceof RefType){
                                    SootClass sootClass1 =((RefType)type).getSootClass();
                                    SootClass first = sootClass1.getInterfaces().getFirst();
                                    if(first.getName().equals("java.lang.Runnable")){
                                        SootMethod method2 = sootClass1.getMethod("void run()");

                                        try {
                                            Edge edge = new Edge(method, (Stmt) next,method2);
                                            callGraph.addEdge(edge);
                                        }catch (Exception e){
//                                            e.printStackTrace();
                                        }

                                        String child = method2.getSignature();
                                        long childId=-1;
                                        if(nodes.keySet().contains(child)){
                                            childId=nodes.get(child);
                                        }else {
                                            nodes.put(child,id);
                                            nodesReverse.put(id,child);
                                            childId=id;
                                            id=id+1;
                                        }
                                        if(parentsInfo.keySet().contains(childId)){
                                            parentsInfo.get(childId).add(parentId);
                                        }else {
                                            ArrayList<Long> parentsList = new ArrayList<>();
                                            parentsList.add(parentId);
                                            parentsInfo.put(childId,parentsList);
                                        }
                                    }
                                }
                            }
                            //生命周期
                            else if(rightOp instanceof JInstanceFieldRef){
                                JInstanceFieldRef rightOp1 = (JInstanceFieldRef) rightOp;
                                String signature = rightOp1.getFieldRef().getSignature();
                                List<String> list = attributes.get(signature);
                                for(String cycleParent:list){
                                    SootMethod method1 = Scene.v().getMethod(cycleParent);
                                    try {
                                        Edge edge = new Edge(method1, (Stmt) next,method);
                                        callGraph.addEdge(edge);
                                    }catch (Exception e){
//                                        e.printStackTrace();
                                    }
                                    parentId=-1;
                                    if(nodes.keySet().contains(cycleParent)){
                                        parentId=nodes.get(cycleParent);
                                    }else {
                                        nodes.put(cycleParent,id);
                                        nodesReverse.put(id,cycleParent);
                                        parentId=id;
                                        id=id+1;
                                    }

                                    String child = method.getSignature();
                                    long childId=-1;
                                    if(nodes.keySet().contains(child)){
                                        childId=nodes.get(child);
                                    }else {
                                        nodes.put(child,id);
                                        nodesReverse.put(id,child);
                                        childId=id;
                                        id=id+1;
                                    }
                                    if(parentsInfo.keySet().contains(childId)){
                                        parentsInfo.get(childId).add(parentId);
                                    }else {
                                        ArrayList<Long> parentsList = new ArrayList<>();
                                        parentsList.add(parentId);
                                        parentsInfo.put(childId,parentsList);
                                    }

                                }
                            }
                        }
                    }catch (Exception e){
                        continue;
                    }
                }

            }
        }
        //反射
        List<Map> reflections = (List) Util.readJsonToMap(reflectionJson).get("items");
        List<Map> reflectionProcessed = new ArrayList<>();
        for(Map reflection:reflections){
            if(reflection.get("type").equals("METHOD_CALL")){
                String parent=(String) reflection.get("methodSignature");
                long parentId=-1;
                if(nodes.keySet().contains(parent)){
                    parentId=nodes.get(parent);
                }else {
                    nodes.put(parent,id);
                    nodesReverse.put(id,parent);
                    parentId=id;
                    id=id+1;
                }
                List<Map> clsSet = (List<Map>) reflection.get("clsSet");
                for(Map cls:clsSet){
                    String clazz=(String) cls.get("cls");
                    String method=(String) cls.get("name");
                    try {
                        SootClass sootClass = Scene.v().getSootClass(clazz);
                        List<Type> paraTypes=getParaTypes(Scene.v().grabMethod(parent),(String)reflection.get("stmt"),method);
                        SootMethod methodByName = sootClass.getMethod(method,paraTypes);
                        String child=methodByName.getSignature();
                        HashMap<String, Object> tmp = new HashMap<>();
                        tmp.put("source",parent);
                        tmp.put("target",child);
                        tmp.put("cls",cls);
                        tmp.put("stmt",reflection.get("stmt"));
                        reflectionProcessed.add(tmp);
                        long childId=-1;
                        if(nodes.keySet().contains(child)){
                            childId=nodes.get(child);
                        }else {
                            nodes.put(child,id);
                            nodesReverse.put(id,child);
                            childId=id;
                            id=id+1;
                        }
                        if(parentsInfo.keySet().contains(childId)){
                            parentsInfo.get(childId).add(parentId);
                        }else {
                            ArrayList<Long> parentsList = new ArrayList<>();
                            parentsList.add(parentId);
                            parentsInfo.put(childId,parentsList);
                        }
                    }catch (Exception e){
                        continue;
                    }
                }
            }
        }


        Map<Long,List> newParentsInfo=new HashMap<>();
        for(Long key :parentsInfo.keySet()){
            List list = parentsInfo.get(key);
            list= (List) list.stream().distinct().collect(Collectors.toList());
            newParentsInfo.put(key,list);
        }
        Scene.v().setCallGraph(callGraph);
        cg.put("nodes",nodes);
        cg.put("node_reverse",nodesReverse);
        cg.put("parents_info",newParentsInfo);
        writeMapToJson(new File(outPut,"cg.json").getAbsolutePath(),cg,false);
        String reflectionEdges = new File(outPut, "reflection_edges.json").getAbsolutePath();
        writeListToJson(reflectionEdges,reflectionProcessed,false);
        insertReflectionUint(reflectionEdges);
        return cg;
    }

    private static HashSet<String> getLifeCycleMethodSig() {
        HashSet<String> lifeCycle = new HashSet<String>();
        lifeCycle.add("onCreate");
        lifeCycle.add("onStart");
        lifeCycle.add("onRestart");
        lifeCycle.add("onResume");
        lifeCycle.add("onPause");
        lifeCycle.add("onStop");
        lifeCycle.add("onDestroy");
        return lifeCycle;
    }

    public static void callGraphGenerate(Chain<SootClass> applicationClasses, CallGraph cg) {
        /**
         * @description: 生成函数调用图
         * @author: xxx
         * @date: 2022/9/28 11:30
         * @param: applicationClasses apk包含类
         * @param: cg 目标调用图存储容器
         * @return: void
         **/
        Body stringBody = Util.getMethodBody("<java.lang.String: void <init>(java.lang.String)>");
        UnitPatchingChain stringBodyUnits = stringBody.getUnits();
        Iterator<Unit> iterator3 = stringBodyUnits.iterator();
        Unit dummy = null;
        while (iterator3.hasNext()){
            Unit next = iterator3.next();
            if(next instanceof JInvokeStmt){
                dummy=next;
                break;
            }
        }
        Iterator<SootClass> iterator = applicationClasses.iterator();
        while (iterator.hasNext()){
            SootClass sootClass = iterator.next();
            List<SootMethod> methods = sootClass.getMethods();
            for(int j=0;j<methods.size();j++){
                SootMethod method = methods.get(j);
                Body activeBody = null;
                try {
                    activeBody = method.retrieveActiveBody();
                }catch (Exception e){
                    continue;
                }
                UnitPatchingChain units = activeBody.getUnits();
                Iterator<Unit> iterator1 = units.iterator();
                while (iterator1.hasNext()){
                    try {
                        Unit next = iterator1.next();
                        String simpleName = next.getClass().getSimpleName();
                        if(simpleName.equals("JInvokeStmt")){
                            JInvokeStmt next1 = (JInvokeStmt) next;
                            SootMethod method1 = next1.getInvokeExpr().getMethod();
                            Edge edge = new Edge(method, (Stmt) next,method1);
                            cg.addEdge(edge);
                            //时间周期函数绑定
                            if(method1.getName().equals("<init>")){
                                Chain<SootClass> interfaces = method1.getDeclaringClass().getInterfaces();
                                if(interfaces.size()>0){
                                    boolean listener=false;
                                    Iterator<SootClass> iterator2 = interfaces.iterator();
                                    while (iterator2.hasNext()){
                                        SootClass next2 = iterator2.next();
                                        if(next2.getPackageName().equals("android.view")){
                                            listener=true;
                                            break;
                                        }
                                    }
                                    if (listener){
                                        List<SootMethod> methods1 = method1.getDeclaringClass().getMethods();
                                        for(SootMethod method3:methods1){
                                            edge = new Edge(method, (Stmt) next,method3);
                                            cg.addEdge(edge);
                                        }
                                    }
                                }
                            }
                        }
                        else if(simpleName.equals("JAssignStmt")){
                            JAssignStmt next1 = (JAssignStmt) next;
                            Value rightOp = next1.getRightOp();
                            String simpleName1 = rightOp.getClass().getSimpleName();
                            if(simpleName1.equals("JVirtualInvokeExpr")||simpleName1.equals("JStaticInvokeExpr")||simpleName1.equals("JSpecialInvokeExpr")||simpleName1.equals("JDynamicInvokeExpr")||simpleName1.equals("JInterfaceInvokeExpr")){
                                AbstractInvokeExpr rightOp1 = (AbstractInvokeExpr) rightOp;
                                SootMethod method1 = Scene.v().grabMethod(rightOp1.getMethodRef().getSignature());
                                Edge edge = new Edge(method, (Stmt) next,method1);
                                cg.addEdge(edge);
                            }else if(simpleName1.equals("JNewExpr")){
                                JNewExpr rightOp1 = (JNewExpr) rightOp;
                                Type type = rightOp1.getType();
                                if(type instanceof RefType){
                                    SootClass sootClass1 =((RefType)type).getSootClass();
                                    SootClass first = sootClass1.getInterfaces().getFirst();
                                    if(first.getName().equals("java.lang.Runnable")){
                                        SootMethod method2 = sootClass1.getMethod("void run()");
                                        Edge edge = new Edge(method, (Stmt) next,method2);
                                        cg.addEdge(edge);
                                    }
                                }
                            }
                        }
                    }catch (Exception e){
                        continue;
                    }
                }
            }

            //抽象类
            SootClass superclass = sootClass.getSuperclass();
            if(!superclass.getName().equals("java.lang.Object")){
                List<SootMethod> methods1 = superclass.getMethods();
                List<SootMethod> methods2 = sootClass.getMethods();
                for(SootMethod parent:methods1){
                    for(SootMethod child:methods2){
                        if(parent.getSubSignature().equals(child.getSubSignature())){
                            Edge edge = new Edge(parent,(Stmt) dummy,child);
                            cg.addEdge(edge);
                            if(child.getSignature().equals("<com.suning.statistics.i.a: byte[] b(byte[],java.lang.String)>")){
                                System.out.println(edge);
                                System.out.println(1);
                            }
                        }
                    }
                }
            }
        }
    }
    public static Map<String, Object> callGraphGenerateEnre(String cgJson,String outPut) throws IOException {
        /**
         * @description: 生成函数调用图,并维护一张查询表,Enre
         * @author: xxx
         * @date: 2022/9/28 11:30
         * @param: applicationClasses apk包含类
         * @param: cg 目标调用图存储容器
         * @return: void
         **/
        Map<String,Object> cg =new HashMap<>();
        Map<String,Long> nodes=new HashMap<>();
        Map<Long,String> nodesReverse=new HashMap<>();
        Map<Long,List> parentsInfo=new HashMap<>();
        List list = readJsonToList(cgJson);
        Iterator iterator = list.iterator();
        long id=0;
        while (iterator.hasNext()){
            Map next = (Map)iterator.next();
            String child = (String) next.get("Tgt");
            long childId=-1;
            if(nodes.keySet().contains(child)){
                childId=nodes.get(child);
            }else {
                nodes.put(child,id);
                nodesReverse.put(id,child);
                childId=id;
                id=id+1;
            }
            String parent = (String) next.get("Src");
            long parentId=-1;
            if(nodes.keySet().contains(parent)){
                    parentId=nodes.get(parent);
                }else {
                    nodes.put(parent,id);
                    nodesReverse.put(id,parent);
                    parentId=id;
                    id=id+1;
                }
            if(parentsInfo.keySet().contains(childId)){
                parentsInfo.get(childId).add(parentId);
            }else {
                ArrayList<Long> parentsList = new ArrayList<>();
                parentsList.add(parentId);
                parentsInfo.put(childId,parentsList);
            }
        }
        cg.put("nodes",nodes);
        cg.put("node_reverse",nodesReverse);
        cg.put("parents_info",parentsInfo);
        writeMapToJson(new File(outPut,"cg.json").getAbsolutePath(),cg,false);
        return cg;
    }
    public static Map<Integer,String> findIdFromR(String path) throws IOException {
        Map<Integer,String> map =new HashMap<>();
        File file=new File(path);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String currentLine="";
        Boolean write=false;
        while ((currentLine=reader.readLine())!=null){
            if(write&&currentLine.contains(" private id() {")){
                write=false;
            }
            if(write){
                if(currentLine.contains("/*")||currentLine.equals("")){
                    continue;
                }
                try {
                    String[] strings = currentLine.split(" ");
                    String idName = strings[strings.length - 3];
                    String id=strings[strings.length - 1];
                    id=id.substring(2,id.length()-1);
                    int i = Integer.parseInt(id, 16);

//                long dec_num=Long.parseLong(id);
                    map.put(i,idName);
                }catch (Exception e){
                    continue;
                }
            }
            if(currentLine.contains("public static final class id {")){
                write=true;
            }

        }
        return map;
    }
    public static List<Long> getParents(String signature,Map<String,Long> nodes,Map<Long,List> parents_info) {
        /**
         * @description: 在函数调用图中寻找目标节点的父亲节点
         * 若没有父亲节点返回为空
         * @author: xxx
         * @date: 2022/9/28 11:40
         * @param: signature
         * @param: cg
         * @return: List<String>
         **/
        List<Long> parents=new ArrayList<>();
        try {
            Long id = nodes.get(signature);
            List list = parents_info.get(id);
            if(list!=null){
                parents=list;
            }
        }catch (Exception e){
            System.out.println("The method has not been used!");
        }
        return parents;
    }
    public static List<Long> getChildren(String signature,Map<String,Long> nodes,Map<Long,List> children_info) {
        /**
         * @description: 在函数调用图中寻找目标节点的父亲节点
         * 若没有父亲节点返回为空
         * @author: xxx
         * @date: 2022/9/28 11:40
         * @param: signature
         * @param: cg
         * @return: List<String>
         **/
        List<Long> children=new ArrayList<>();
        try {
            Long id = nodes.get(signature);
            List list = children_info.get(id);
            if(list!=null){
                children=list;
            }
        }catch (Exception e){
            System.out.println("The method has no child!");
        }
        return children;
    }
    public static Map<String,Map> immediateBoxPares(JimpleBody body){
        /**
         * @description:函数体局部变量解析，局部变量的类型，函数调用ref,是否依赖于参数
         * @author: xxx
         * @date: 2022/12/13 19:28
         * @param:
         * @param: body 函数体
         * @return: Map<String,Object>
         **/
        Map<String,Map> result=new HashMap<>();
        Chain<Local> locals = body.getLocals();
        Iterator<Local> iterator = locals.iterator();
        while (iterator.hasNext()){
            Local next = iterator.next();
            String name = next.getName().toString();
            String type = next.getType().toString();
            HashMap<String, Object> map = new HashMap<>();
            map.put("type",type);
            map.put("isPara",false);
            map.put("relyOnPara",false);
            result.put(name,map);
        }
        UnitPatchingChain bodyUnits = body.getUnits();
        Iterator<Unit> iterator1 = bodyUnits.iterator();
        while (iterator1.hasNext()){
            Unit next = iterator1.next();
            String unitType = next.getClass().getSimpleName();
            if(unitType.equals("JIdentityStmt")){
                JIdentityStmt identityStmt = (JIdentityStmt) next;
                String local = identityStmt.getLeftOp().toString();
                Object isPara = result.get(local).get("isPara");
                isPara=true;
            }
            else if(unitType.equals("JAssignStmt")){
                JAssignStmt assignStmt = (JAssignStmt) next;
                String local = assignStmt.getLeftOp().toString();
                Value rightOp = assignStmt.getRightOp();
                String rightOpType = rightOp.getClass().getSimpleName();
                if(rightOpType.equals("StringConstant")){
                    result.get(local).put("constant",rightOp.toString());
                }
                else if(rightOpType.equals("JVirtualInvokeExpr")){

                }

            }


        }


        return result;
    }
    public static Body getMethodBody(String signature){
        /**
         * @description: 通过方法签名拿到方法体
         * @author: xxx
         * @date: 2022/12/26 20:45
         * @param:
         * @param: signature 方法签名
         * @return: Body 方法体
         **/
        SootMethod method = Scene.v().grabMethod(signature);
        return method.retrieveActiveBody();
    }
    public static Map<String,Set> urlRegexMatching(String source,Pattern ipRegex,Pattern urlRegex, Pattern urlRegex1){
        Map<String,Set> results=new HashMap<>();
        Matcher ipMatcher = ipRegex.matcher(source);
        HashSet<String> ipSet = new HashSet<>();
        while (ipMatcher.find()){
            String ip = ipMatcher.group();
            ipSet.add(ip);
        }
        results.put("ip",ipSet);
        HashSet<String> urlSet = new HashSet<>();
        Matcher urlMatcher = urlRegex.matcher(source);
        while (urlMatcher.find()){
            String url = urlMatcher.group();
            if(!url.contains("schemas.android.com")){
                urlSet.add(url);
            }
        }
        Matcher urlMatcher1 = urlRegex1.matcher(source);
        while (urlMatcher1.find()){
            String url = urlMatcher1.group();
            urlSet.add(url);
        }
        results.put("url",urlSet);
        return results;
    }
    public static List<String> readFile(String path){
        List<String> results = new ArrayList<>();
        File file = new File(path);
        if(file.isFile() && file.exists()){
            try {
                FileInputStream fileInputStream = new FileInputStream(file);
                InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String text = null;
                while((text = bufferedReader.readLine()) != null){
                    results.add(text);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return results;
    }
    public static List<List> getPathes(String child,Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        /**
         * @description: 拿到所有调用路径
         * @author: xxx
         * @date: 2022/9/28 11:41
         * @param: child
         * @param: cg
         * @return: List<Map>
         **/
        int maxSize=30000;
        Set<List> results=new HashSet<>();
        Queue<List> queue=new LinkedList<>();
        List<Long> parents = getParents(child,nodes,parents_info);
        Long childId = nodes.get(child);
        HashSet<String> areadyAdded = new HashSet<>();
        for(int i =0; i<parents.size();i++){
            List<Long> list =new ArrayList<>();
            Long parent = parents.get(i);
            list.add(childId);
            list.add(0,parent);
            queue.add(list);
        }
        while (!queue.isEmpty()){
            List head = queue.poll();
            if(head.size()<30){
                String sig = nodeReverse.get(head.get(0));
                List<Long> parents1 = getParents(sig,nodes,parents_info);
                if(parents1.size()==0){
                    String key=head.get(0)+""+head.get(head.size()-1);
                    if(areadyAdded.contains(key)){
                        continue;
                    }
                    areadyAdded.add(key);
                    results.add(head);
                    if(results.size()>maxSize){
                        break;
                    }
                }else {
                    for(int i =0; i<parents1.size();i++){
                        Long parent = parents1.get(i);
                        //破环
                        if(head.contains(parent)){
                            if(head.get(0).equals(parent)){
                                results.add(head);
                            }
                            continue;
                        }
                        List<Long> list =new ArrayList<>();
                        list.addAll(head);
                        list.add(0,parent);
                        queue.add(list);
                    }
                }
            }
        }
        ArrayList<List> res = new ArrayList<>();
        for(List<Long> list: results){
            ArrayList<String> tmpList = new ArrayList<>();
            for(int i=0;i<list.size();i++){
                Long id = list.get(i);
                tmpList.add(nodeReverse.get(id));
            }
            res.add(tmpList);
        }
        return res;
    }
    public static Set<String> findComponentIdInMethod(SootMethod method){
        //$r3 = virtualinvoke $r2.<android.view.LayoutInflater: android.view.View inflate(int,android.view.ViewGroup,boolean)>(2131558767, null, 0)
        Set<String> results =new HashSet<>();
        try {
            Body body = method.retrieveActiveBody();
            Iterator<Unit> iterator = body.getUnits().iterator();
            while (iterator.hasNext()){
                Unit next = iterator.next();
                String nextStr = next.toString();
                if (next instanceof JAssignStmt){
                    JAssignStmt jAssignStmt = (JAssignStmt) next;
                    Value value = jAssignStmt.getRightOpBox().getValue();
                    if(value instanceof JVirtualInvokeExpr){
                        JVirtualInvokeExpr value1 = (JVirtualInvokeExpr) value;
                        if(value1.getMethodRef().toString().contains("android.view.View findViewById(int)>")){
                            Value value2 = value1.getArgs().get(0);
                            if(value2 instanceof IntConstant){
                                results.add(value2.toString());
                            }else {
                                results.add(method.getSignature()+value2.toString());
                            }

                        }
                    }
                }
                else if(next instanceof JInvokeStmt){
                    JInvokeStmt next1 = (JInvokeStmt) next;
                    InvokeExpr invokeExpr = next1.getInvokeExpr();
                    if(invokeExpr.getMethodRef().toString().contains("android.view.View findViewById(int)>")){
                        Value value = invokeExpr.getArgs().get(0);
                        if(value instanceof IntConstant){
                            results.add(value.toString());
                        }else {
                            results.add(method.getSignature()+value.toString());
                        }
                    }
                }
                if(nextStr.contains("213")){
                    if(nextStr.contains(">")){
                        String[] split = nextStr.split(">")[1].split(",");
                        String subString=null;
                        for(String str:split){
                            if(str.contains("213")){
                                subString=str;
                            }
                        }
                        String result = Pattern.compile("[^0-9]").matcher(subString).replaceAll("").trim();
                        results.add(result);
                    }

                }
            }
        }catch (Exception e){
            return results;
        }
        return results;
    }
    public static List<Map> findViewIdForSensitiveScenes(List<Map> netTrans){
        /**
         * @description:找到敏感场景对应的敏感场景
         * @author: xxx
         * @date: 2023/2/16 15:21
         * @param:
         * @param: netTrans 敏感场景列表，元素字典中需要有键invoke_chain;
         * @return: List<Map>
         **/
        for(int i=0;i<netTrans.size();i++){
            Map map = netTrans.get(i);
            List<String> invoke_chain = (List)map.get("invoke_chain");
            List<Map> componentIdList=new ArrayList<>();
            for(String api:invoke_chain){
                try {
                    Map<String,Object> componentId=new HashMap<>();
                    Set<String> componentIdInMethod = Util.findComponentIdInMethod(Scene.v().grabMethod(api));
                    componentId.put(api,componentIdInMethod);
                    componentIdList.add(componentId);
                }catch (Exception e){
                    continue;
                }
            }
            map.put("component_id",componentIdList);
        }
        return netTrans;
    }
    public static Map<String,String> eventsBinding(SootMethod source){
        /**
         * @description: 输入事件，返回哪些控件绑定了该事件
         * @author: xxx
         * @date: 2022/10/30 11:25
         * @param:
         * @param: method 含有findViewByid()的函数
         * @return: List<String> 事件绑定控件的id
         **/
        Map<String,String> result=new HashMap<>();
//        SootMethod source=Scene.v().grabMethod(method);
        Body b=source.retrieveActiveBody();
        UnitPatchingChain units = b.getUnits();
        Iterator<Unit> iterator = units.iterator();
        List<Unit> unitList=new ArrayList<>();
        while (iterator.hasNext()){
            unitList.add(iterator.next());
        }
        for(int i=0;i<unitList.size();i++){
            Unit unit = unitList.get(i);
            if(unit.getClass().getSimpleName().equals("JInvokeStmt")){
                JInvokeStmt invokeStmt = (JInvokeStmt) unit;
                InvokeExpr invokeExpr = invokeStmt.getInvokeExpr();
                //OnClickListener
                if(invokeExpr.getMethodRef().toString().equals("<android.view.View: void setOnClickListener(android.view.View$OnClickListener)>")){
                    String events = invokeExpr.getArgs().get(0).getType().toString();
                    String idRef=invokeExpr.getUseBoxes().get(0).getValue().toString();
                    for (int j=i-1;j>=0;j--){
                        Unit unit1 = unitList.get(j);
                        if (unit1.getClass().getSimpleName().equals("JAssignStmt")){
                            JAssignStmt jAssignStmt = (JAssignStmt) unit1;
                            if(jAssignStmt.getLeftOpBox().getValue().toString().equals(idRef)){
                                Value value = jAssignStmt.getRightOpBox().getValue();
                                if(value.getClass().getSimpleName().equals("JVirtualInvokeExpr")){
                                    JVirtualInvokeExpr value1 = (JVirtualInvokeExpr) value;
                                    if(value1.getMethodRef().toString().contains("android.view.View findViewById(int)>")){
                                        result.put(events,value1.getArgs().get(0).toString());
                                        break;
                                    }
                                }

                            }

                        }
                    }
                }
            }

        }
        return result;
    }
    public static Map getComponentInfo(String jsonPath) throws IOException {
        Gson gson = new Gson();
        File file = new File(jsonPath);
        InputStreamReader streamReader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(streamReader);
        String content="";
        StringBuilder builder = new StringBuilder();
        while ((content = bufferedReader.readLine()) != null)
            builder.append(content);
        Map componentInfo = gson.fromJson(builder.toString(), Map.class);
        return componentInfo;
    }
    public static Map readJsonToMap(String jsonPath) throws IOException {
        Gson gson = new Gson();
        File file = new File(jsonPath);
        InputStreamReader streamReader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(streamReader);
        String content="";
        StringBuilder builder = new StringBuilder();
        while ((content = bufferedReader.readLine()) != null)
            builder.append(content);
        Map map = gson.fromJson(builder.toString(), Map.class);
        return map;
    }
    public static List readJsonToList(String jsonPath) throws IOException {
        Gson gson = new Gson();
        File file = new File(jsonPath);
        InputStreamReader streamReader = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(streamReader);
        String content="";
        StringBuilder builder = new StringBuilder();
        while ((content = bufferedReader.readLine()) != null)
            builder.append(content);
        List list = gson.fromJson(builder.toString(), List.class);
        return list;
    }
    public static void removeMutiElement(List<Map> netTrans){
        Set<String> set=new HashSet<>();
        for(int i=netTrans.size()-1;i>=0;i--){
            Map map = netTrans.get(i);
            List<String> invoke_chain = (List)map.get("invoke_chain");
            String s = invoke_chain.toString();
            if(set.contains(s)){
                netTrans.remove(i);
            }else {
                set.add(s);
            }
        }

    }
    public static void decompiled(String path,String output_dir){
        /**
         * @description: 使用jadx反编译apk文件
         * @author: xxx
         * @date: 2022/9/20 18:00
         * @param: path apk文件路径
         * @param: output_dir 输出路径
         * @return: void
         **/
        JadxArgs jadxArgs = new JadxArgs();
        jadxArgs.setInputFile(new File(path));
        jadxArgs.setOutDir(new File(output_dir));
        try (JadxDecompiler jadx = new JadxDecompiler(jadxArgs)) {
            jadx.load();
            jadx.save();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static List<Map> readSourceAndSinkFile(String sourceAndSinkFile) throws IOException {
        /**
         * @description: 读sourcesandsink.txt 忽略注释，换行信息
         * @author: xxx
         * @date: 2022/9/22 15:03
         * @param: sourceAndSinkFile txt文件路径
         * @return: List<Map> 敏感API列表
         **/
        List<Map> api=new ArrayList<>();
        File file=new File(sourceAndSinkFile);
        if(file.exists()&&file.isFile()){
            FileInputStream fileInputStream = new FileInputStream(file);
            InputStreamReader inputStreamReader = new InputStreamReader(fileInputStream);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            String text=null;
            while((text = bufferedReader.readLine()) != null){
                if(text.equals("")||text.charAt(0)=='%'){
                    continue;
                }
                String[] split = text.split(" -> ");
                try {
                    Map<String,Object> map=new HashMap<>();
                    map.put("api",split[0]);
                    map.put("type",split[1]);
                    api.add(map);
                }catch (Exception e){
                    continue;
                }

            }


        }
        return api;
    }
    public static void callGraphToJson(CallGraph cg,String jsonPath){
        List<Map> jsonList=new ArrayList();
        Iterator<Edge> iterator = cg.iterator();
        while (iterator.hasNext()){
            Edge next = iterator.next();
            try {
                String tgt = next.getTgt().method().getSignature();
                String src = next.getSrc().method().getSignature();
                Map<String,String> map=new HashMap<>();
                map.put("Src",src);
                map.put("Tgt",tgt);
                jsonList.add(map);
            }catch (Exception e){
                continue;
            }
        }
        writeListToJson(jsonPath,jsonList,false);
    }
    public static void mixDynamicCg(Map<String, Long> nodes, Map<Long, String> nodeReverse, Map<Long, List> parents_info,String dynamicCgJson) throws IOException {
        Map dynamicCg = readJsonToMap(dynamicCgJson);
        int size = nodes.size();
        Map<String,Set> nodesMap=new HashMap<>();
        for(String key:nodes.keySet()){
            String[] keyList = key.split(" ");
            String packageName = keyList[0].substring(1, keyList[0].length() - 1);
            String method = keyList[2].split("\\(")[0];
            String newKey=packageName+"."+method;
            if(nodesMap.containsKey(newKey)){
                Set set = nodesMap.get(newKey);
                set.add(key);
            }else {
                HashSet<Object> tmpSet = new HashSet<>();
                tmpSet.add(key);
                nodesMap.put(newKey,tmpSet);
            }
        }
        Map map =dynamicCg;
        if(dynamicCg.containsKey("result")){
            map = (Map) dynamicCg.get("result");
        }
        List<Map> dynamicNodes = (List<Map>) map.get("nodes");
        Set<String> nodeSet = nodesMap.keySet();
        for(Map node:dynamicNodes){
            Map nodeMap = (Map) node.get("value");
            String method = (String) nodeMap.get("name");
            if(!nodeSet.contains(method)){
                long id = (long) size++;
                nodes.put(method,id);
                nodeReverse.put(id,method);
                HashSet hashSet = new HashSet();
                hashSet.add(method);
                nodesMap.put(method,hashSet);
            }
        }
        List<Map> dynamicEdges = (List<Map>) map.get("edges");
        Map<String,Set> dynamicParentsInfo=new HashMap<>();
        for(Map<String,Map> edge:dynamicEdges){
            Map sourceMap = (Map) edge.get("source").get("value");
            String sourceMethod = (String) sourceMap.get("name");
            Map targetMap = (Map) edge.get("target").get("value");
            String targetMethod = (String) targetMap.get("name");
            if(dynamicParentsInfo.containsKey(targetMethod)){
                Set set = dynamicParentsInfo.get(targetMethod);
                set.add(sourceMethod);
            }else {
                HashSet<String> set = new HashSet<>();
                set.add(sourceMethod);
                dynamicParentsInfo.put(targetMethod,set);
            }
        }
        for(String key:dynamicParentsInfo.keySet()){
            Set<String> parents = dynamicParentsInfo.get(key);
            HashSet<Long> parentsId = new HashSet<>();
            for(String parent:parents){
                Set<String> parentSigSet = nodesMap.get(parent);
                for(String parentSig :parentSigSet){
                    parentsId.add(nodes.get(parentSig));
                }
            }
            Set<String> targetSet = nodesMap.get(key);
            for(String targetSig : targetSet){
                Long targetId = nodes.get(targetSig);
                if(parents_info.containsKey(targetId)){
                    List parentsList = parents_info.get(targetId);
                    for(Long id:parentsId){
                        if(!parentsList.contains(id)){
                            parentsList.add(id);
                        }
                    }
                }else {
                    List parentsList = new ArrayList();
                    for(Long id:parentsId){
                        if(!parentsList.contains(id)){
                            parentsList.add(id);
                        }
                    }
                    parents_info.put(targetId,parentsList);
                }
            }

        }
    }
    public static void activityTransGraphGenerate(SetupApplication setupApplication,String outPut) throws UnsupportedEncodingException {
        HashMap<String, List> graph = new HashMap<>();
        IComponentContainer activities = setupApplication.getMainfest().getActivities();
        System.out.println(activities);
        HashMap<String, List> activityTargetActionMap= new HashMap<>();
        ArrayList<String> activityStrings = new ArrayList<>();
        Iterator iterator = activities.iterator();
        while (iterator.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity)iterator.next();
            String activity = next.getNameString();
            activityStrings.add(activity);
            List<AXmlNode> children = next.getAXmlNode().getChildren();
            ArrayList<String> actions = new ArrayList<>();
            for(AXmlNode child:children){
                if(child.getTag().equals("intent-filter")){
                    List<AXmlNode> children1 = child.getChildren();
                    for(AXmlNode child1:children1){
                        if(child1.getTag().equals("action")){
                            String action = (String) child1.getAttribute("name").getValue();
                            actions.add(action);
                        }
                    }
                }
            }
            activityTargetActionMap.put(activity,actions);
        }

        //通过action跳转
        Iterator iterator1 = activities.iterator();
        while (iterator1.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity)iterator1.next();
            String activity = next.getNameString();
            String onCreate="<"+activity+": void onCreate(android.os.Bundle)>";
            try {
                String onCreateBody = Util.getMethodBody(onCreate).toString();
                for(String target:activityTargetActionMap.keySet()){
                    List<String> actionList = activityTargetActionMap.get(target);
                    for(String action:actionList){
                        if(onCreateBody.contains(action)){
                            if(graph.containsKey(activity)){
                                graph.get(activity).add(target);
                            }else {
                                ArrayList<String> tmp = new ArrayList<>();
                                tmp.add(target);
                                graph.put(activity,tmp);
                            }
                            break;
                        }
                    }
                }
            }catch (Exception e){
                continue;
            }
        }

        //通过classname跳转
        Iterator iterator2 = activities.iterator();
        while (iterator2.hasNext()){
            BinaryManifestActivity next = (BinaryManifestActivity)iterator2.next();
            String activity = next.getNameString();
            String onCreate="<"+activity+": void onCreate(android.os.Bundle)>";
            try {
                String onCreateBody = Util.getMethodBody(onCreate).toString();
                for(String target:activityStrings){
                    if(target.equals(activity)){
                        continue;
                    }
                    String[] split = target.split("\\.");
                    String activityName = split[split.length - 1];
                    if(onCreateBody.contains(activityName+".class")){
                        if(graph.containsKey(activity)){
                            graph.get(activity).add(target);
                        }else {
                            ArrayList<String> tmp = new ArrayList<>();
                            tmp.add(target);
                            graph.put(activity,tmp);
                        }
                        break;
                    }else if(onCreateBody.contains(target)){
                        if(graph.containsKey(activity)){
                            graph.get(activity).add(target);
                        }else {
                            ArrayList<String> tmp = new ArrayList<>();
                            tmp.add(target);
                            graph.put(activity,tmp);
                        }
                        break;
                    }else if(onCreateBody.contains(target.replace(".","/"))){
                        if(graph.containsKey(activity)){
                            graph.get(activity).add(target);
                        }else {
                            ArrayList<String> tmp = new ArrayList<>();
                            tmp.add(target);
                            graph.put(activity,tmp);
                        }
                        break;
                    }
                }
            }catch (Exception e){
                continue;
            }
        }
        Util.writeListToJson1(new File(outPut,"activities.json").getAbsolutePath(),activityStrings,false);
        Util.writeMapToJson(new File(outPut,"activity_trans_graph.json").getAbsolutePath(),graph,false);
        System.out.println(1);
    }
    public static List<Type> getParaTypes(SootMethod sourceMethod, String stmt, String methodName){
        Body sourceBody = getMethodBody(sourceMethod.getSignature());
        String tgtStmt=removeDigital(stmt).replace("$","");
        String method="\""+methodName+"\"";
        UnitPatchingChain unitsChain = sourceBody.getUnits();
        Iterator<Unit> iterator = unitsChain.iterator();
        ArrayList<Unit> unitsArray = new ArrayList<>();
        while (iterator.hasNext()){
            unitsArray.add(iterator.next());
        }
        int right=0,left=0;
        //找出调用地方
        for(int i=0;i<unitsArray.size();i++){
            Unit unit = unitsArray.get(i);
            String unitStr = unit.toString();
            if(unitStr.contains(method)){
                //更加精细的匹配，待＋
                for(int j=i+1;j<unitsArray.size();j++){
                    Unit unit1 = unitsArray.get(j);
                    String unit1Str = removeDigital(unit1.toString()).replace("$","");
                    if(unit1Str.equals(tgtStmt)){
                        right=j;
                        break;
                    }
                }
                break;
            }
        }
        if(right==0){
            for(int i=0;i<unitsArray.size();i++){
                Unit unit = unitsArray.get(i);
                if(tgtStmt.equals(removeDigital(unit.toString()).replace("$",""))){
                    right=i;
                }
            }
        }
        Unit unit = unitsArray.get(right);
        String paraName="";
        if(unit instanceof JInvokeStmt){
            JInvokeStmt unit1 = (JInvokeStmt) unit;
            Value arg = unit1.getInvokeExpr().getArg(1);
            JimpleLocal arg1 = (JimpleLocal) arg;
            paraName=arg1.getName();
        }
        else if(unit instanceof JAssignStmt){
            JAssignStmt unit1 = (JAssignStmt) unit;
            Value rightOp = unit1.getRightOp();
            JVirtualInvokeExpr rightOp1 = (JVirtualInvokeExpr) rightOp;
            Value arg = rightOp1.getArg(1);
            JimpleLocal arg1 = (JimpleLocal) arg;
            paraName=arg1.getName();
        }
        for(int i=right-1;i>0;i--){
            Unit unit1 = unitsArray.get(i);
            if(unit1 instanceof JAssignStmt){
                JAssignStmt unit11 = (JAssignStmt) unit1;
                Value rightOp = unit11.getRightOp();
                if(rightOp instanceof JNewArrayExpr){
                    if(unit11.getLeftOp().toString().equals(paraName)){
                        left=i;
                        break;
                    }
                }
            }
        }
        //寻找参数列表
        List<Value> paraList = new ArrayList<>();
        for(int i=left+1;i<right;i++){
            Unit unit1 = unitsArray.get(i);
            if(unit1 instanceof JAssignStmt){
                JAssignStmt unit2 = (JAssignStmt) unit1;
                Value leftOp = unit2.getLeftOp();
                if(leftOp instanceof JArrayRef){
                    JArrayRef leftOp1 = (JArrayRef) leftOp;
                    if(leftOp1.getBase().toString().equals(paraName)){
                        int index = Integer.parseInt(leftOp1.getIndex().toString());
                        Value rightOp = unit2.getRightOp();
                        paraList.add(index,rightOp);
                    }
                }
            }
        }
        ArrayList<Type> types = new ArrayList<>();
        for(Value v :paraList){
            types.add(v.getType());
        }
        return types;
    }
    public static void insertReflectionUint(String reflectionJson) throws IOException {
        /**
         * @description: 根据反射调用边，在caller的body中插入指定语句
         * @author: xxx
         * @date: 2023/9/19 10:17
         * @param:
         * @param: reflectionJson
         * @return: void
         **/
        List<Map> reflections = readJsonToList(reflectionJson);
        for(Map reflection:reflections){
            SootMethod sourceMethod = Scene.v().getMethod((String) reflection.get("source"));
            Body sourceBody = getMethodBody((String) reflection.get("source"));
            String tgtStmt=removeDigital((String) reflection.get("stmt")).replace("$","");
            Map map = (Map) reflection.get("cls");
            String clazz="\""+(String) map.get("cls")+"\"";
            String method="\""+(String) map.get("name")+"\"";
            UnitPatchingChain unitsChain = sourceBody.getUnits();
            Iterator<Unit> iterator = unitsChain.iterator();
            ArrayList<Unit> unitsArray = new ArrayList<>();
            while (iterator.hasNext()){
                unitsArray.add(iterator.next());
            }
            int right=0,left=0;
            //找出调用地方
            for(int i=0;i<unitsArray.size();i++){
                Unit unit = unitsArray.get(i);
                String unitStr = unit.toString();
                if(unitStr.contains(method)){
                    //更加精细的匹配，待＋
                    for(int j=i+1;j<unitsArray.size();j++){
                        Unit unit1 = unitsArray.get(j);
                        String unit1Str = removeDigital(unit1.toString()).replace("$","");
                        if(unit1Str.equals(tgtStmt)){
                            right=j;
                            break;
                        }
                    }
                    break;
                }
            }
            if(right==0){
                for(int i=0;i<unitsArray.size();i++){
                    Unit unit = unitsArray.get(i);
                    if(tgtStmt.equals(removeDigital(unit.toString()).replace("$",""))){
                        right=i;
                    }
                }
            }
            Unit unit = unitsArray.get(right);
            String paraName="";
            Value leftReturn = null;
            if(unit instanceof JInvokeStmt){
                JInvokeStmt unit1 = (JInvokeStmt) unit;
                Value arg = unit1.getInvokeExpr().getArg(1);
                JimpleLocal arg1 = (JimpleLocal) arg;
                paraName=arg1.getName();
            }
            else if(unit instanceof JAssignStmt){
                JAssignStmt unit1 = (JAssignStmt) unit;
                Value rightOp = unit1.getRightOp();
                leftReturn = unit1.getLeftOp();
                JVirtualInvokeExpr rightOp1 = (JVirtualInvokeExpr) rightOp;
                Value arg = rightOp1.getArg(1);
                JimpleLocal arg1 = (JimpleLocal) arg;
                paraName=arg1.getName();
            }
            for(int i=right-1;i>0;i--){
                Unit unit1 = unitsArray.get(i);
                if(unit1 instanceof JAssignStmt){
                    JAssignStmt unit11 = (JAssignStmt) unit1;
                    Value rightOp = unit11.getRightOp();
                    if(rightOp instanceof JNewArrayExpr){
                        if(unit11.getLeftOp().toString().equals(paraName)){
                            left=i;
                            break;
                        }
                    }
                }
            }
            //寻找参数列表
            List<Value> paraList = new ArrayList<>();
            for(int i=left+1;i<right;i++){
                Unit unit1 = unitsArray.get(i);
                if(unit1 instanceof JAssignStmt){
                    JAssignStmt unit2 = (JAssignStmt) unit1;
                    Value leftOp = unit2.getLeftOp();
                    if(leftOp instanceof JArrayRef){
                        JArrayRef leftOp1 = (JArrayRef) leftOp;
                        if(leftOp1.getBase().toString().equals(paraName)){
                            int index = Integer.parseInt(leftOp1.getIndex().toString());
                            Value rightOp = unit2.getRightOp();
                            paraList.add(index,rightOp);
                        }
                    }
                }
            }
            //构造unit 并插入body
            //构造调用
            SootMethod target = Scene.v().getMethod((String) reflection.get("target"));
            SootMethodRefImpl sootMethodRef = new SootMethodRefImpl(target.getDeclaringClass(), target.getName(), target.getParameterTypes(), target.getReturnType(), true);
            JStaticInvokeExpr jStaticInvokeExpr = new JStaticInvokeExpr(sootMethodRef, paraList);
            if(leftReturn!=null){
                JAssignStmt jAssignStmt = new JAssignStmt(leftReturn, jStaticInvokeExpr);
                //插入body
                Unit sourceUnit = unitsArray.get(right);
                Unit targetUnit = unitsChain.getSuccOf(sourceUnit);
                unitsChain.insertOnEdge(jAssignStmt,sourceUnit,targetUnit);
//                unitsArray.add(right+1,jAssignStmt);
//                unitsChain.clear();
//                unitsChain.addAll(unitsArray);

            }else {
                JInvokeStmt jInvokeStmt = new JInvokeStmt(jStaticInvokeExpr);
                //插入body
                Unit sourceUnit = unitsArray.get(right);
                Unit targetUnit = unitsChain.getSuccOf(sourceUnit);
                unitsChain.insertOnEdge(jInvokeStmt,sourceUnit,targetUnit);
            }
        }
    }
    public static String removeDigital(String value){
        Pattern p = Pattern.compile("[\\d]");
        Matcher matcher = p.matcher(value);
        String result = matcher.replaceAll("");
        return result;
    }

}
