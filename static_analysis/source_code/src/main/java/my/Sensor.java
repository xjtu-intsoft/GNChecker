package my;

import org.checkerframework.checker.units.qual.A;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.AssignStmt;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.internal.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.util.Chain;

import java.io.IOException;
import java.util.*;

/**
 * @description:
 * @author: xxx
 * @date: 2023/2/10 10:34
 **/
public class Sensor {

    public static List<Map> findSensorFromCoed(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        List<Map> results =new ArrayList<>();
        Set<String> sinkApis =new HashSet<>();
        sinkApis.add("<android.hardware.SensorManager: java.util.List getDynamicSensorList(int)>");
        sinkApis.add("<android.hardware.SensorManager: java.util.List getSensorList(int)>");
        sinkApis.add("<android.hardware.SensorManager: android.hardware.Sensor getDefaultSensor(int,boolean)>");
        sinkApis.add("<android.hardware.SensorManager: android.hardware.Sensor getDefaultSensor(int)>");
        for(String api:sinkApis){
            List<Long> tmpParents = Util.getParents(api, nodes, parents_info);
            List<String> parents =new ArrayList<>();
            for(Long id :tmpParents){
                parents.add(nodeReverse.get(id));
            }
            for(String parent:parents){
                try {
                    Body methodBody = Util.getMethodBody(parent);
                    UnitPatchingChain units = methodBody.getUnits();
                    List<Unit> list=new ArrayList<>();
                    Iterator<Unit> iterator = units.iterator();
                    while (iterator.hasNext()){
                        list.add(iterator.next());
                    }
                    for (int i=0;i<list.size();i++){
                        Unit unit = list.get(i);
                        if(unit instanceof AssignStmt){
                            JAssignStmt assignStmt = (JAssignStmt) unit;
                            Value rightOp = assignStmt.getRightOp();
                            if(rightOp instanceof JVirtualInvokeExpr){
                                JVirtualInvokeExpr rightOp1 = (JVirtualInvokeExpr) rightOp;
                                if(rightOp1.toString().contains(api)){
                                    Value arg = rightOp1.getArg(0);
                                    if(arg instanceof IntConstant){
                                        Map<String, Object> map = new HashMap<>();
                                        map.put("api",api);
                                        map.put("sensor", arg.toString());
                                        map.put("location", parent);
                                        results.add(map);
                                    }
                                    else if(arg instanceof JimpleLocal){
                                        String local = arg.toString();
                                        for(int j=i-1;j>0;j--){
                                            Unit unit1 = list.get(j);
                                            if(unit1 instanceof JAssignStmt){
                                                JAssignStmt unit11 = (JAssignStmt) unit1;
                                                Value leftOp = unit11.getLeftOp();
                                                if(leftOp instanceof JimpleLocal){
                                                    if(leftOp.toString().equals(local)){
                                                        Map<String, Object> map = new HashMap<>();
                                                        map.put("api",api);
                                                        map.put("sensor", unit11.getRightOp().toString());
                                                        map.put("location", parent);
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
                }catch (Exception e){
                    continue;
                }
            }
        }
        return results;
    }
    public static List<Map> findSensorFromCode1(Map<String,Long> nodes,Map<Long,String> nodeReverse,Map<Long,List> parents_info){
        List<Map> results =new ArrayList<>();
        Set<String> sinkApis =new HashSet<>();
        sinkApis.add("<android.hardware.SensorManager: java.util.List getDynamicSensorList(int)>");
        sinkApis.add("<android.hardware.SensorManager: java.util.List getSensorList(int)>");
        sinkApis.add("<android.hardware.SensorManager: android.hardware.Sensor getDefaultSensor(int,boolean)>");
        sinkApis.add("<android.hardware.SensorManager: android.hardware.Sensor getDefaultSensor(int)>");
        for(String api:sinkApis){
//            List<Long> tmpParents = Util.getParents(api, nodes, parents_info);
//            List<String> parents =new ArrayList<>();
//            for(Long id :tmpParents){
//                parents.add(nodeReverse.get(id));
//            }
            List<List> pathes = Util.getPathes(api, nodes, nodeReverse, parents_info);
            for(List<String> path:pathes){
                try {
                    String parent=path.get(path.size()-2);
                    Body methodBody = Util.getMethodBody(parent);
                    UnitPatchingChain units = methodBody.getUnits();
                    List<Unit> list=new ArrayList<>();
                    Iterator<Unit> iterator = units.iterator();
                    while (iterator.hasNext()){
                        list.add(iterator.next());
                    }
                    for (int i=0;i<list.size();i++){
                        Unit unit = list.get(i);
                        if(unit instanceof AssignStmt){
                            JAssignStmt assignStmt = (JAssignStmt) unit;
                            Value rightOp = assignStmt.getRightOp();
                            if(rightOp instanceof JVirtualInvokeExpr){
                                JVirtualInvokeExpr rightOp1 = (JVirtualInvokeExpr) rightOp;
                                if(rightOp1.toString().contains(api)){
                                    Value arg = rightOp1.getArg(0);
                                    if(arg instanceof IntConstant){
                                        Map<String, Object> map = new HashMap<>();
                                        map.put("api",api);
                                        map.put("sensor", arg.toString());
                                        map.put("invoke_chain",path);
                                        results.add(map);
                                    }
                                    else if(arg instanceof JimpleLocal){
                                        String local = arg.toString();
                                        for(int j=i-1;j>0;j--){
                                            Unit unit1 = list.get(j);
                                            if(unit1 instanceof JAssignStmt){
                                                JAssignStmt unit11 = (JAssignStmt) unit1;
                                                Value leftOp = unit11.getLeftOp();
                                                if(leftOp instanceof JimpleLocal){
                                                    if(leftOp.toString().equals(local)){
                                                        Map<String, Object> map = new HashMap<>();
                                                        map.put("api",api);
                                                        map.put("sensor", unit11.getRightOp().toString());
                                                        map.put("invoke_chain",path);
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
                }catch (Exception e){
                    continue;
                }
            }
        }
        return results;
    }
}
