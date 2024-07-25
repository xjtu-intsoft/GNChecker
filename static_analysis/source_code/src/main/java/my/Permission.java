package my;

import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.internal.AbstractInvokeExpr;
import soot.jimple.internal.JArrayRef;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.util.Chain;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @description:
 * @author: xxx
 * @date: 2023/2/10 10:40
 **/
public class Permission {
    public static List<Map> findUsedPermissionFromCode(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        /**
         * @description: 从代码层面寻找目标apk使用了哪些权限
         * 权限信息存储在属性permissionsFromCode中
         * @author: xxx
         * @date: 2022/11/1 15:57
         * @param:
         * @param: cg apk 函数调用图
         * @return: void
         **/

        List<Map> permissionsFromCode =new ArrayList<>();
        Map<String,Integer> sinkApis =new HashMap<>();
        sinkApis.put("<androidx.core.app.ActivityCompat: void requestPermissions(android.app.Activity,java.lang.String[],int)>",1);
        sinkApis.put("<androidx.fragment.app.Fragment: void requestPermissions(java.lang.String[],int)>",0);
        for(String api : sinkApis.keySet()){
            List<Long> tmpParents = Util.getParents(api, nodes, parents_info);
            List<String> parents =new ArrayList<>();
            for(Long id :tmpParents){
                parents.add(nodeReverse.get(id));
            }
            if(parents.size()>0){
                for(String parent:parents){
                    SootMethod source= Scene.v().grabMethod(parent);
                    Body b=source.retrieveActiveBody();
                    Iterator<Unit> iterator = b.getUnits().iterator();
                    List<Unit> unitList = new ArrayList<>();
                    while (iterator.hasNext()){
                        unitList.add(iterator.next());
                    }
                    for(int i=0;i<unitList.size();i++){
                        Unit unit = unitList.get(i);
                        if(unit.getClass().getSimpleName().equals("JInvokeStmt")){
                            JInvokeStmt jInvokeStmt = (JInvokeStmt) unit;
                            InvokeExpr invokeExpr = jInvokeStmt.getInvokeExpr();
                            if(invokeExpr.getMethodRef().toString().equals(api)){
                                Value value = invokeExpr.getArgs().get(sinkApis.get(api));
                                String local = value.toString();
                                for(int j=i-1;j>=0;j--){
                                    Unit unit1 = unitList.get(j);
                                    if(unit1.getClass().getSimpleName().equals("JAssignStmt")){
                                        JAssignStmt jAssignStmt = (JAssignStmt) unit1;
                                        Value leftOp = jAssignStmt.getLeftOp();
                                        if(leftOp.getClass().getSimpleName().equals("JArrayRef")){
                                            JArrayRef leftOp1 = (JArrayRef) leftOp;
                                            if(leftOp1.getBase().toString().equals(local)){
                                                Map map=new HashMap();
                                                map.put("permisson",jAssignStmt.getRightOp().toString().replace("\"",""));
                                                map.put("api",api);
                                                map.put("location",parent);
                                                permissionsFromCode.add(map);
                                            }
                                        }

                                    }
                                }
                            }

                        }
                    }
                }
            }
        }

        return permissionsFromCode;
    }
    public static List<Map> findUsedPermissionFromCodePlus(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        /**
         * @description: 从代码层面寻找目标apk使用了哪些权限
         * 权限信息存储在属性permissionsFromCode中
         * @author: xxx
         * @date: 2022/11/1 15:57
         * @param:
         * @param: cg apk 函数调用图
         * @return: void
         **/
        String p = "\"([^\"]*)\"" ;
        Pattern pattern= Pattern.compile(p);
        List<Map> permissionsFromCode =new ArrayList<>();
        List<String> permissionApi = findPermissionApi(nodes);
        for (String api:permissionApi){
            List<Long> tmpParents = Util.getParents(api, nodes, parents_info);
            List<String> parents =new ArrayList<>();
            for(Long id :tmpParents){
                parents.add(nodeReverse.get(id));
            }
            for(String parent:parents){
                Body methodBody = Util.getMethodBody(parent);
                UnitPatchingChain units = methodBody.getUnits();
                Iterator<Unit> iterator = units.iterator();
                while (iterator.hasNext()){
                    Unit next = iterator.next();
                    String str = next.toString();
                    if(str.contains(api)){
                        Matcher matcher = pattern.matcher(str);
                        if(matcher.find()){
                            System.out.println(matcher.group(0));
                            Map map=new HashMap();
                            map.put("permission",matcher.group(0));
                            map.put("api",api);
                            map.put("location",parent);
                            permissionsFromCode.add(map);
                        }
                    }
                }
            }
        }
        return permissionsFromCode;
    }
    public static List<Map> findUsedPermissionFromCodePlus1(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        /**
         * @description: 从代码层面寻找目标apk使用了哪些权限
         * 权限信息存储在属性permissionsFromCode中
         * @author: xxx
         * @date: 2022/11/1 15:57
         * @param:
         * @param: cg apk 函数调用图
         * @return: void
         **/
        ArrayList<String> permissionApi = new ArrayList<>();
        permissionApi.add("<androidx.core.app.ActivityCompat: void requestPermissions(android.app.Activity,java.lang.String[],int)>");
        permissionApi.add("<androidx.fragment.app.Fragment: void requestPermissions(java.lang.String[],int)>");
        String p = "\"([^\"]*)\"" ;
        Pattern pattern= Pattern.compile(p);
        List<Map> permissionsFromCode =new ArrayList<>();
        for (String api:permissionApi){
            List<List> pathes = Util.getPathes(api, nodes, nodeReverse, parents_info);
//            List<Long> tmpParents = Util.getParents(api, nodes, parents_info);
//            List<String> parents =new ArrayList<>();
//            for(Long id :tmpParents){
//                parents.add(nodeReverse.get(id));
//            }
            for(List<String> path:pathes){
                String parent=path.get(path.size()-2);
                Body methodBody = Util.getMethodBody(parent);
                UnitPatchingChain units = methodBody.getUnits();
                Iterator<Unit> iterator = units.iterator();
                while (iterator.hasNext()){
                    Unit next = iterator.next();
                    String str = next.toString();
                    if(str.contains(api)){
                        Matcher matcher = pattern.matcher(str);
                        if(matcher.find()){
                            System.out.println(matcher.group(0));
                            Map map=new HashMap();
                            map.put("permission",matcher.group(0));
                            map.put("api",api);
                            map.put("invoke_chain",path);
                            permissionsFromCode.add(map);
                        }
                    }
                }
            }
        }
        return permissionsFromCode;
    }
    public static List<String> findPermissionApi(Map<String,Long> nodes){
        ArrayList<String> results = new ArrayList<>();
        Set<String> actionSet=new HashSet<>();
        actionSet.add("permission");
        Iterator<String> iterator = nodes.keySet().iterator();
        Map<String,Map> methodMap=new HashMap();
        while (iterator.hasNext()){
            String next = iterator.next();
           try{
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
            boolean b=false;
            String next = iterator1.next();
            Map map = methodMap.get(next);

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
            if(b){
                results.add(next);
            }
        }
        return results;
    }
}
