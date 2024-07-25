package secondstage.taintanalysis.analyzer;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.mxgraph.layout.mxCompactTreeLayout;
import com.mxgraph.layout.mxIGraphLayout;
import com.mxgraph.util.mxCellRenderer;
import my.Util;
import org.jgrapht.ext.JGraphXAdapter;
import org.jgrapht.graph.DefaultEdge;
import secondstage.taintanalysis.TaintConfig;
import secondstage.taintanalysis.taint.*;
import soot.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.util.Chain;

import secondstage.taintanalysis.SinkSource.SinkSourceBuilder;
import secondstage.taintanalysis.SinkSource.SinkSourceMethod;


import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;


public class TaintAnalyzer {
//    public static int MaxTaintTreeLength = 500;
//    public static int MaxTaintTreeCount = 80;
//    public static int OneSourceHasMaxSinks = 20;
//    public static int OneSourceHasMaxMays = 1;
//    public static int MaxEdgeCount = 4;
    public static int MaxTaintTreeLength = 65;
    public static int MaxTaintTreeCount = 80;
    public static int OneSourceHasMaxSinks = 2;
    public static int OneSourceHasMaxMays = 1;
    public static int MaxEdgeCount = 4;
//    public static int MaxTaintTreeLength = 500;
//    public static int MaxTaintTreeCount = 500;
//    public static int OneSourceHasMaxSinks = 20;
//    public static int OneSourceHasMaxMays = 1;
//    public static int MaxEdgeCount = 1000;
    public static PrintWriter FileOut;
    public static ClassAnalyzer classAnalyzer;
    public static TaintResult taintResult;
    public static TaintWraperBuilder taintWraperBuilder;
    public static TaintSet TaintS;
    public static ArrayList<TaintValue> SinkS;
    public static ArrayList<TaintValue> May;
    public static SinkSourceBuilder sinkSourceBuilder;
    public static TaintMethodSet taintMethodset;
    public static int ClassNum;
    public static int MethodNum;
    public static int StateMNum;
    public static IInfoflowCFG iCfg;
    public static FileOutput fOutput;
    public static int limitedRound;
    public static String ClassMethodName;
    private long beforeFlowDroid;
    private long beforeFastDroid;
    public EfficiencyResult efficiencyResult;
    public ArrayList<ArrayList<TaintValue>> TaintFlowAfterCheck;
    public ArrayList<ArrayList<TaintValue>> TaintFlowUniqueAfterCheck;
    public CallGraph cg;
    public TaintConfig fconfig;
    private SetupApplication analyzer = null;
    public ProcessManifest manifest = null;
    public String outDir;
    public String classJson;
    public String callbacks;

    public void initialize(TaintConfig config) throws IOException {
        this.callbacks=config.getCallbacks();
        this.outDir=config.getOutDir();
        this.classJson=config.getClassJson();
        this.fconfig = config;
        taintMethodset = new TaintMethodSet();
        TaintS = new TaintSet();
        May = new ArrayList<>();
        classAnalyzer = new ClassAnalyzer(TaintS);
        ClassAnalyzer.fastMode = config.isFastMode();
        ClassAnalyzer.pathSen = config.isPathSen();
        limitedRound = config.getLimitedRound();
        SinkS = new ArrayList<>();
        ClassNum = 0;
        MethodNum = 0;
        StateMNum = 0;
        String fileOutPutPath = config.getOutputFile();
        if (fileOutPutPath != null) {
            fOutput = new FileOutput(config.getApkPath(), config.getApkName(), fileOutPutPath);
        } else {
            fOutput = null;
        }
        String PathOfSummary = config.getSummary();
        String PathOfSourceSink = config.getSourceSinkFilePath();
        this.efficiencyResult = new EfficiencyResult();
        if (PathOfSummary == null || PathOfSourceSink == null) {
            System.err.println("The File of TaintWrapper or SourceSink is not set up!");
            System.exit(0);
            return;
        }
        taintWraperBuilder = new TaintWraperBuilder(config.getSummary());
        taintWraperBuilder.Build();
        CreateSourceSink(config.getSourceSinkFilePath());
//        CreateStartActivitySinks(outDir);
    }

    private void CreateStartActivitySinks(String outDir) throws IOException {
        List<String> list = Util.readJsonToList(new File(outDir, "activities.json").getAbsolutePath());
        for(String activity : list){
            String line="<"+activity+": void startActivity(android.content.Intent)>";
            int j12 = line.indexOf("<");
            int m12 = line.indexOf(":");
            int k12 = line.indexOf("(");
            int k22 = line.indexOf(")");
            SinkSourceMethod ss2 = new SinkSourceMethod();
            if (j12 + 1 < m12) {
                ss2.setClassname(line.substring(j12 + 1, m12));
            }
            new String();
            if (m12 + 2 < k12 && line.substring(m12 + 2, k12).contains(" ")) {
                String temp12 = line.substring(m12 + 2, k12);
                int t2 = temp12.indexOf(" ");
                int tl2 = temp12.length();
                ss2.setReturnType(temp12.substring(0, t2));
                ss2.setMethodname(temp12.substring(t2 + 1, tl2));
            }
            new String();
            if (k12 + 1 < k22) {
                String temp22 = line.substring(k12 + 1, k22);
                ArrayList<String> para2 = new ArrayList<>();
                int num2 = 1;
                while (temp22.indexOf(",") > 0) {
                    int x2 = temp22.indexOf(",");
                    num2++;
                    para2.add(temp22.substring(0, x2));
                    temp22 = temp22.substring(x2 + 1, temp22.length());
                }
                ss2.setParanum(num2);
                para2.add(temp22);
                ss2.setParaType(para2);
            }
            sinkSourceBuilder.getSinkSet().add(ss2);
        }
    }

    private long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
    public ArrayList<List> my_run(InfoflowAndroidConfiguration config) throws IOException {
        if (fOutput != null) {
            fOutput.printName();
        }
        this.beforeFlowDroid = System.nanoTime();
        try {
            this.analyzer = new SetupApplication(config);
            String apkpath = config.getAnalysisFileConfig().getTargetAPKFile();
            this.analyzer.setCallbackFile(this.callbacks);
            File apkF = new File(apkpath);
            this.efficiencyResult.apkSize = apkF.length() / 1000;

            int codeSize = 0;
            for (SootClass SCC : Scene.v().getClasses()) {
                for (SootMethod sm : SCC.getMethods()) {
                    if (sm.hasActiveBody()) {
                        codeSize += sm.getActiveBody().getUnits().size();
                    }
                }
            }
            this.efficiencyResult.codeSize = codeSize;
            this.manifest = new ProcessManifest(config.getAnalysisFileConfig().getTargetAPKFile());
            this.efficiencyResult.timeOfCreateCFG = (System.nanoTime() - this.beforeFlowDroid) / 1.0E9d;
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.beforeFastDroid = System.nanoTime();

        System.out.println("Starting the taint analyse...");
        ArrayList<List> taintFlows = analyzeIter(this.classJson);
//        writeFiles(taintFlows,new File(this.outDir,"taint_flow.json").getAbsolutePath());
        writeFiles1(taintFlows,new File(this.outDir,"taint_flow.json").getAbsolutePath());
        this.efficiencyResult.timeOfFastDroidTaintAnalize = (System.nanoTime() - this.beforeFastDroid) / 1.0E9d;
//        printResult();
        return taintFlows;
    }
    public void run_dex(InfoflowAndroidConfiguration config) throws IOException {
        if (fOutput != null) {
            fOutput.printName();
        }
        this.beforeFlowDroid = System.nanoTime();
        try {
            this.analyzer = new SetupApplication(config);
            String apkpath = config.getAnalysisFileConfig().getTargetAPKFile();
            this.analyzer.setCallbackFile(this.callbacks);
            File apkF = new File(apkpath);
            this.efficiencyResult.apkSize = apkF.length() / 1000;

            int codeSize = 0;
            for (SootClass SCC : Scene.v().getClasses()) {
                for (SootMethod sm : SCC.getMethods()) {
                    if (sm.hasActiveBody()) {
                        codeSize += sm.getActiveBody().getUnits().size();
                    }
                }
            }
            this.efficiencyResult.codeSize = codeSize;
//            this.manifest = new ProcessManifest(config.getAnalysisFileConfig().getTargetAPKFile());
            this.efficiencyResult.timeOfCreateCFG = (System.nanoTime() - this.beforeFlowDroid) / 1.0E9d;
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.beforeFastDroid = System.nanoTime();

        System.out.println("Starting the taint analyse...");
        ArrayList<List> taintFlows = analyzeIter_dex(this.classJson);
        writeFiles(taintFlows,new File(this.outDir,"taint_flow.json").getAbsolutePath());
        this.efficiencyResult.timeOfFastDroidTaintAnalize = (System.nanoTime() - this.beforeFastDroid) / 1.0E9d;
//        printResult();
    }
    private ArrayList<List> analyzeIter_dex(String jsonPath) throws IOException {
        List<List> classList = Util.readJsonToList(jsonPath);
        Iterator<List> iterator = classList.iterator();
        ArrayList<List> results = new ArrayList<>();
        int count=0;
        while (iterator.hasNext()){
            List<String> next = iterator.next();
            classAnalyzer.clear();
            for(String sig :next){
                classAnalyzer.add(Scene.v().getSootClass(sig));
            }
            taintResult = new TaintResult(TaintS, this.cg, SinkS, May);
            classAnalyzer.searchSourceAndSink();
            classAnalyzer.taintAnalysis(limitedRound);
            TaintS= classAnalyzer.taintSet;
            System.out.println("Constructing the taint flow...");
            System.out.println(count);
            count++;
            taintResult = new TaintResult(TaintS, this.cg, SinkS, May);
            ArrayList<List> taintResultFlows = taintResult.createFlows();
            taintResult.checkFlows(taintResultFlows);
            results.addAll(taintResultFlows);
        }
        return results;
    }
    private ArrayList<List> analyzeIter(String jsonPath) throws IOException {
        List<List> classList = Util.readJsonToList(jsonPath);
        Iterator<List> iterator = classList.iterator();
        ArrayList<List> results = new ArrayList<>();
        int count=0;
        while (iterator.hasNext()){
            List<String> next = iterator.next();
            classAnalyzer.clear();
            for(String sig :next){
                classAnalyzer.add(Scene.v().getSootClass(sig));
            }
            taintResult = new TaintResult(TaintS, this.cg, SinkS, May);
            classAnalyzer.searchSourceAndSink();
            classAnalyzer.taintAnalysis(limitedRound);
            TaintS= classAnalyzer.taintSet;
            System.out.println("Constructing the taint flow...");
            System.out.println(count);
            count++;
            taintResult = new TaintResult(TaintS, this.cg, SinkS, May);
            ArrayList<List> taintResultFlows = taintResult.createFlows();
            taintResult.checkFlows(taintResultFlows);
            ArrayList<List>flows=IccCheck(taintResultFlows,this.outDir);
            results.addAll(flows);
        }
        return results;
    }

    private ArrayList<List> IccCheck(ArrayList<List> taintResultFlows,String outDir) throws IOException {
        ArrayList<List> results = new ArrayList<>();
        Iterator<List> iterator = taintResultFlows.iterator();
        HashMap<String, List> intentMap = new HashMap<>();
        HashMap<String, List> startActivityMap = new HashMap<>();
        while (iterator.hasNext()){
            List<List> next = iterator.next();
            Iterator<List> iterator1 = next.iterator();
            while (iterator1.hasNext()){
                List next1 = iterator1.next();
                int size = next1.size();
                TaintValue sink = (TaintValue) next1.get(size - 1);
                TaintValue source = (TaintValue) next1.get(0);
                Boolean hasIntent=false;
                Boolean hasStartActivity=false;
                if(source.getSL().getStatement().toString().contains("getIntent")){
                    hasIntent=true;
                    String activity = source.gettClass();
                    if(intentMap.keySet().contains(activity)){
                        intentMap.get(activity).add(next1);
                    }else {
                        ArrayList<List> tmp = new ArrayList<>();
                        tmp.add(next1);
                        intentMap.put(activity,tmp);
                    }
                }
                if(sink.getSL().getStatement().toString().contains("startActivity")){
                    hasStartActivity=true;
                    String activity = sink.gettClass();
                    if(startActivityMap.keySet().contains(activity)){
                        startActivityMap.get(activity).add(next1);
                    }else {
                        ArrayList<List> tmp = new ArrayList<>();
                        tmp.add(next1);
                        startActivityMap.put(activity,tmp);
                    }
                }
                if(!hasIntent&&!hasStartActivity){
                    results.add(next1);
                }
            }
        }
        Map<String,List> graph = Util.readJsonToMap(new File(outDir, "activity_trans_graph.json").getAbsolutePath());
        for(String source: startActivityMap.keySet()){
            if(graph.containsKey(source)){
                List<String> targets = graph.get(source);
                for(String target:targets){
                    if(intentMap.containsKey(target)){
                        List<List> lists = startActivityMap.get(source);
                        List<List> lists1 = intentMap.get(target);
                        for(List first:lists){
                            for(List second:lists1){
                                List tmp = new ArrayList<>();
                                tmp.addAll(first);
                                tmp.addAll(second);
                                results.add(tmp);
                            }

                        }
                    }
                }
            }
        }
//        System.out.println(taintResultFlows);
        return results;
    }

    public void run(InfoflowAndroidConfiguration config) throws IOException {
        if (fOutput != null) {
            fOutput.printName();
        }
        this.beforeFlowDroid = System.nanoTime();
        try {
            this.analyzer = new SetupApplication(config);
            String apkpath = config.getAnalysisFileConfig().getTargetAPKFile();
            this.analyzer.setCallbackFile("D:\\cert\\input\\callbacktest.txt");
            File apkF = new File(apkpath);
            this.efficiencyResult.apkSize = apkF.length() / 1000;
            this.analyzer.constructCallgraph();

            int codeSize = 0;
            for (SootClass SCC : Scene.v().getClasses()) {
                for (SootMethod sm : SCC.getMethods()) {
                    if (sm.hasActiveBody()) {
                        codeSize += sm.getActiveBody().getUnits().size();
                    }
                }
            }
            this.efficiencyResult.codeSize = codeSize;
            this.manifest = new ProcessManifest(config.getAnalysisFileConfig().getTargetAPKFile());
            this.efficiencyResult.timeOfCreateCFG = (System.nanoTime() - this.beforeFlowDroid) / 1.0E9d;
            System.out.println("The above information is from the FlowDroid. Now start the FastDroid anaysis!!");
            System.out.println("CFG Construction has run for " + this.efficiencyResult.timeOfCreateCFG + " seconds");
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.beforeFastDroid = System.nanoTime();
        ConstructAllClasses();
        taintResult = new TaintResult(TaintS, this.cg, SinkS, May);
        if (0 == 0) {
            System.out.println("Searching the Sources and Sinks...");
            classAnalyzer.searchSourceAndSink();
            if (TaintS.isEmpty()) {
                System.out.println("------------------------RESULT--------------------------------------");
                System.out.println("No source exists!!");
            }
            System.out.println("Starting the taint analyse...");
            classAnalyzer.taintAnalysis(limitedRound);
//            classAnalyzer.taintAnalysisBaseMethod(limitedRound);
            System.out.println("All taint value is as follows:------------------------");
            System.out.println("Constructing the taint flow...");
            //可视化图
//            flowVisual();
            taintResult = new TaintResult(TaintS, this.cg, SinkS, May);
            taintResult.createAndCheckFLows();
        }

        this.efficiencyResult.timeOfFastDroidTaintAnalize = (System.nanoTime() - this.beforeFastDroid) / 1.0E9d;
        printResult();
    }
    private void writeFiles1(ArrayList<List> taintResultFlows,String filePath) {
        HashSet<Integer> set = new HashSet<>();
        Iterator<List> iterator = taintResultFlows.iterator();
        JsonFactory factory = new JsonFactory();
        int count=0;
        try{
            JsonGenerator generator = factory.createGenerator(new File(filePath), JsonEncoding.UTF8);
            generator.writeStartArray();
            while (iterator.hasNext()){
                List<TaintValue> next1 = iterator.next();
                ArrayList<String> strings = new ArrayList<>();
                Iterator iterator2 = next1.iterator();
                String str="";
                while (iterator2.hasNext()){
                    TaintValue next = (TaintValue)iterator2.next();
                    String tv= next.toString();
                    str+=tv;
                    strings.add(tv);
                }if(!set.contains(str.hashCode())){
//                    fileContent.add(strings);
                    generator.writeStartArray();
                    for(String s:strings){
                        generator.writeString(s);
                    }
                    generator.writeEndArray();
                    count+=1;
                    set.add(str.hashCode());
                }
            }
            generator.writeEndArray();
            generator.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("found flows: "+count+" !!!");
//        Util.writeListToJson2(filePath,fileContent,false);
    }

    private void writeFiles(ArrayList<List> taintResultFlows,String filePath) {
        ArrayList<List> fileContent = new ArrayList<>();
        HashSet<String> set = new HashSet<>();
        Iterator<List> iterator = taintResultFlows.iterator();
        while (iterator.hasNext()){
                List<TaintValue> next1 = iterator.next();
                ArrayList<String> strings = new ArrayList<>();
                Iterator iterator2 = next1.iterator();
                String str="";
                while (iterator2.hasNext()){
                    String tv=iterator2.next().toString();
                    str+=tv;
                    strings.add(tv);
                }
                if(!set.contains(str)){
                    fileContent.add(strings);
                    set.add(str);
                }

        }
        System.out.println("found flows: "+fileContent.size()+" !!!");
        Util.writeListToJson2(filePath,fileContent,false);
    }


    private void flowVisual() throws IOException {
        Iterator<TaintFlow> iterator = TaintS.allTFlows.iterator();
        while (iterator.hasNext()){
            TaintFlow next = iterator.next();
            JGraphXAdapter<Integer, DefaultEdge> graphXAdapter=new JGraphXAdapter<Integer, DefaultEdge>(next.Pairs);
            mxIGraphLayout mxIGraphLayout = new mxCompactTreeLayout(graphXAdapter);
            mxIGraphLayout.execute(graphXAdapter.getDefaultParent());

            BufferedImage bufferedImage = mxCellRenderer.createBufferedImage(graphXAdapter, null, 3, Color.WHITE, true, null);
            String path="C:\\Users\\77294\\Desktop\\fastdroid_test\\imgs\\"+next.taintFlowID+".png";
            File newFIle = new File(path);
            ImageIO.write(bufferedImage, "PNG", newFIle);
        }
    }

    private void printResult() {
        System.out.println("------------------------RESULT--------------------------------------");
        System.out.println("Totally analysis:" + ClassNum + " Classes，" + MethodNum + " Methods，" + StateMNum + " Statements");
        System.out.println(TaintS.allTFlows.size() + " Sources and " + SinkS.size() + " Sinks are detected");
        System.out.println("All TaintFlows are as follows:-------------------------");
        taintResult.printTaintSimple();
        taintResult.printTaintNum();
        System.out.println("Analyse round is :---------" + ClassAnalyzer.RoundAnalyse + "---------------");
        System.out.println("--------------------------Taint result after check--------------------------------------");
        long maxMemoryConsumption = getUsedMemory();
        this.efficiencyResult.maxMemoryConsumption = maxMemoryConsumption / 1000000.0d;
        System.out.println("Maximum memory consumption: " + this.efficiencyResult.maxMemoryConsumption + " MB");
        System.out.println("APK size is : " + this.efficiencyResult.apkSize + " KB");
        System.out.println("Code Size is " + this.efficiencyResult.codeSize + " lines");
        System.out.println("FastDroid detectes " + taintResult.taintFlowsResult.size() + " taint flows");
        System.out.println("FastDroid detectes " + taintResult.mayFlowsResult.size() + " may taint flows");
        System.out.println("Fastdroid analysis has totally run for " + this.efficiencyResult.timeOfFastDroidTaintAnalize + " seconds");
        System.out.println("--------------------------FINISH--------------------------------------");
        if (fOutput != null) {
            fOutput.printNum(ClassNum, MethodNum, StateMNum);
            fOutput.printSourceandSink(taintResult);
            fOutput.printFinal(this.efficiencyResult, taintResult.taintFlowsResult.size(), taintResult.mayFlowsResult.size());
            fOutput.close();
        }
    }

    private void printResultDetail() {
        System.out.println("------------------------RESULT--------------------------------------");
        System.out.println("Totally analysis:" + ClassNum + " Classes，" + MethodNum + " Methods，" + StateMNum + " Statements");
        System.out.println("All taint value is as follows:------------------------");
        System.out.println("All sink value is as follows:-------------------------");
        Iterator<TaintValue> it = SinkS.iterator();
        while (it.hasNext()) {
            TaintValue tv = it.next();
            System.out.println(tv.toString());
        }
        System.out.println("All may sink value is as follows:-------------------------");
        Iterator<TaintValue> it2 = May.iterator();
        while (it2.hasNext()) {
            TaintValue tv2 = it2.next();
            System.out.println(tv2.toString());
        }
        System.out.println("All TaintFlow is as follows:-------------------------");
        taintResult.printTaint();
        taintResult.printTaintNum();
        taintResult.printPath();
        System.out.println("All Implicit FaintFlow is as follows:------------------------");
        taintResult.printMayTaint();
        System.out.println("Analyse round is :---------" + ClassAnalyzer.RoundAnalyse + "---------------");
        System.out.println("--------------------------Taint result after check--------------------------------------");
        long maxMemoryConsumption = getUsedMemory();
        this.efficiencyResult.maxMemoryConsumption = maxMemoryConsumption / 1000000.0d;
        System.out.println("Maximum memory consumption: " + this.efficiencyResult.maxMemoryConsumption + " MB");
        System.out.println("APK size is : " + this.efficiencyResult.apkSize + " KB");
        System.out.println("Code Size is " + this.efficiencyResult.codeSize + " lines");
        System.out.println("FastDroid detectes " + taintResult.taintFlowsResult.size() + " taint flows");
        System.out.println("FastDroid detectes " + taintResult.mayFlowsResult.size() + " taint flows");
        System.out.println("Fastdroid analysis has totally run for " + this.efficiencyResult.timeOfFastDroidTaintAnalize + " seconds");
        System.out.println("--------------------------FINISH--------------------------------------");
        if (fOutput != null) {
            fOutput.printNum(ClassNum, MethodNum, StateMNum);
            fOutput.printSourceandSink(taintResult);
            fOutput.printFinal(this.efficiencyResult, taintResult.taintFlowsResult.size(), taintResult.mayFlowsResult.size());
            fOutput.close();
        }
    }

    protected void printTaintFlow(ArrayList<ArrayList<TaintValue>> taintFlows) {
        int i = 1;
        Iterator<ArrayList<TaintValue>> it = taintFlows.iterator();
        while (it.hasNext()) {
            ArrayList<TaintValue> tf = it.next();
            System.out.println("Taintflow" + i + ":");
            int m = 0;
            Iterator<TaintValue> it2 = tf.iterator();
            while (it2.hasNext()) {
                TaintValue tv = it2.next();
                int i2 = m;
                m++;
                System.out.print(i2 + ":");
                System.out.println(tv.toString());
            }
            i++;
        }
    }

    protected void CreateSourceSink(String file) {
        if ("flowdroid".equals("susi")) {
            sinkSourceBuilder = new SinkSourceBuilder("res/Files/Sinks.txt", "res/Files/Sources.txt");
            sinkSourceBuilder.BuildSink();
            sinkSourceBuilder.BuildSource();
        }
        if ("flowdroid".equals("flowdroid")) {
            sinkSourceBuilder = new SinkSourceBuilder(file);
            sinkSourceBuilder.Build();
        }
    }

    private boolean filterClass(SootClass SClass) {
        String className = SClass.getName();
        if (!className.startsWith(this.manifest.getPackageName() + ".R") && !SClass.isJavaLibraryClass() && !className.startsWith("android.")) {
            return true;
        }
        return false;
    }
    private void ConstructClassesFromJson(String jsonPath) throws IOException {
        List<String> classList = Util.readJsonToList(jsonPath);
        for(String clazz:classList){
            SootClass sootClass = Scene.v().getSootClass(clazz);
            classAnalyzer.add(sootClass);
        }
    }
    private void ConstructMethod(String jsonPath) throws IOException {
        List<String> methodList = Util.readJsonToList(jsonPath);
        for(String method:methodList){
            SootMethod sm = Scene.v().getMethod(method);
            classAnalyzer.addMethod(sm);
        }
    }
    protected void ConstructAllClasses() {
        Chain<SootClass> appClasses = Scene.v().getApplicationClasses();
        Chain<SootClass> totalclass2 = Scene.v().getLibraryClasses();
        Chain<SootClass> totalclass1 = Scene.v().getClasses();
        Iterator<SootClass> Iter = appClasses.snapshotIterator();
//        //根据控制流加载所需类
//        SootClass sootClass = Scene.v().getSootClass("com.sina.weibo.sdk.utils.AidTask");
//        classAnalyzer.add(sootClass);
//        while (Iter.hasNext()){
//            SootClass next = Iter.next();
//            String packageName = next.getPackageName();
//            if(packageName.contains("com.sina.weibo.sdk.net")){
//                classAnalyzer.add(next);
//            }
//        }
        while (Iter.hasNext()) {
            SootClass SC = Iter.next();
            if (filterClass(SC) && !classAnalyzer.have(SC)) {
                classAnalyzer.add(SC);
            }
        }
        Iterator<SootClass> Iter2 = totalclass2.snapshotIterator();
        while (Iter2.hasNext()) {
            SootClass SC2 = Iter2.next();
            if (filterClass(SC2) && !classAnalyzer.have(SC2)) {
                classAnalyzer.add(SC2);
            }
        }
        Iterator<SootClass> Iter3 = totalclass1.snapshotIterator();
        while (Iter3.hasNext()) {
            SootClass SC3 = Iter3.next();
            if (filterClass(SC3) && !classAnalyzer.have(SC3)) {
                classAnalyzer.add(SC3);
            }
        }
    }
}
