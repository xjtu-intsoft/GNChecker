package secondstage.taintanalysis;

import secondstage.taintanalysis.analyzer.TaintAnalyzer;
import org.apache.commons.cli.*;
import org.apache.log4j.spi.LocationInfo;
import org.jboss.util.property.PropertyManager;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.config.XMLConfigurationParser;
import soot.jimple.infoflow.methodSummary.xml.XMLConstants;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class TaintLauncher {
    public static TaintAnalyzer taintAnalyser;
    private final Options options = new Options();
    public static ArrayList<String> argsFastdroid = new ArrayList<>();
    public static ArrayList<String> argsFlowdroid = new ArrayList<>();
    private static final String OPTION_CONFIG_FILE = "c";
    private static final String OPTION_APK_FILE = "a";
    private static final String OPTION_PLATFORMS_DIR = "p";
    private static final String OPTION_SOURCES_SINKS_FILE = "s";
    private static final String OPTION_OUTPUT_FILE = "o";
    private static final String OPTION_TIMEOUT = "dt";
    private static final String OPTION_CALLBACK_TIMEOUT = "ct";
    private static final String OPTION_RESULT_TIMEOUT = "rt";
    private static final String OPTION_NO_STATIC_FLOWS = "ns";
    private static final String OPTION_NO_CALLBACK_ANALYSIS = "nc";
    private static final String OPTION_NO_EXCEPTIONAL_FLOWS = "ne";
    private static final String OPTION_NO_TYPE_CHECKING = "nt";
    private static final String OPTION_REFLECTION = "r";
    private static final String OPTION_TAINT_WRAPPER = "tw";
    private static final String OPTION_TAINT_WRAPPER_FILE = "t";
    private static final String OPTION_ACCESS_PATH_LENGTH = "al";
    private static final String OPTION_FLOW_INSENSITIVE_ALIASING = "af";
    private static final String OPTION_COMPUTE_PATHS = "cp";
    private static final String OPTION_ONE_SOURCE = "os";
    private static final String OPTION_ONE_COMPONENT = "ot";
    private static final String OPTION_SEQUENTIAL_PATHS = "sp";
    private static final String OPTION_LOG_SOURCES_SINKS = "ls";
    private static final String OPTION_MERGE_DEX_FILES = "d";
    private static final String OPTION_SINGLE_JOIN_POINT = "sa";
    private static final String OPTION_MAX_CALLBACKS_COMPONENT = "mc";
    private static final String OPTION_MAX_CALLBACKS_DEPTH = "md";
    private static final String OPTION_PATH_SPECIFIC_RESULTS = "ps";
    private static final String OPTION_ICC_MODEL = "im";
    private static final String OPTION_ICC_NO_PURIFY = "np";
    private static final String OPTION_CALLGRAPH_ALGO = "cg";
    private static final String OPTION_LAYOUT_MODE = "l";
    private static final String OPTION_PATH_RECONSTRUCTION_ALGO = "pa";
    private static final String OPTION_CALLBACK_ANALYZER = "ca";
    private static final String OPTION_DATA_FLOW_SOLVER = "ds";
    private static final String OPTION_ALIAS_ALGO = "aa";
    private static final String OPTION_CODE_ELIMINATION_MODE = "ce";
    private static final String OPTION_CALLBACK_SOURCE_MODE = "cs";
    private static final String OPTION_PATH_RECONSTRUCTION_MODE = "pr";
    private static final String OPTION_IMPLICIT_FLOW_MODE = "i";
    private static final String OPTION_OUTPUT_FASTDROID_FILE = "Fo";
    private static final String OPTION_LIMITED_ROUND = "Flr";
    private static final String OPTION_TAINT_METHOD_SUMMARY = "Ftw";
    private static final String OPTION_FLOW_SENSITIVITY = "Ffs";
    private static final String OPTION_PATH_SENSITIVITY = "Fps";
    private static final String OPTION_FAST_MODE = "Fmd";

    private void initializeCommandLineOptions() {
        this.options.addOption(LocationInfo.NA, "help", false, "Print this help message");
        this.options.addOption(OPTION_CONFIG_FILE, "configfile", true, "Use the given configuration file");
        this.options.addOption(OPTION_APK_FILE, "apkfile", true, "APK file to analyze");
        this.options.addOption(OPTION_PLATFORMS_DIR, "platformsdir", true, "Path to the platforms directory from the Android SDK");
        this.options.addOption(OPTION_SOURCES_SINKS_FILE, "sourcessinksfile", true, "Definition file for sources and sinks");
        this.options.addOption(OPTION_OUTPUT_FILE, "outputfile", true, "Output XML file for the discovered data flows");
        this.options.addOption(OPTION_TIMEOUT, "timeout", true, "Timeout for the main data flow analysis");
        this.options.addOption(OPTION_CALLBACK_TIMEOUT, "callbacktimeout", true, "Timeout for the callback collection phase");
        this.options.addOption(OPTION_RESULT_TIMEOUT, "resulttimeout", true, "Timeout for the result collection phase");
        this.options.addOption(OPTION_NO_STATIC_FLOWS, "nostatic", false, "Do not track static data flows");
        this.options.addOption(OPTION_NO_CALLBACK_ANALYSIS, "nocallbacks", false, "Do not analyze Android callbacks");
        this.options.addOption(OPTION_NO_EXCEPTIONAL_FLOWS, "noexceptions", false, "Do not track taints across exceptional control flow edges");
        this.options.addOption(OPTION_NO_TYPE_CHECKING, "notypechecking", false, "Disable type checking during taint propagation");
        this.options.addOption(OPTION_REFLECTION, "enablereflection", false, "Enable support for reflective method calls");
        this.options.addOption(OPTION_TAINT_WRAPPER, "taintwrapper", true, "Use the specified taint wrapper algorithm (NONE, EASY, STUBDROID, MULTI)");
        this.options.addOption(OPTION_TAINT_WRAPPER_FILE, "taintwrapperfile", true, "Definition file for the taint wrapper");
        this.options.addOption(OPTION_ACCESS_PATH_LENGTH, "aplength", true, "Maximum access path length");
        this.options.addOption(OPTION_FLOW_INSENSITIVE_ALIASING, "aliasflowins", false, "Use a flow-insensitive alias analysis");
        this.options.addOption(OPTION_COMPUTE_PATHS, "paths", false, "Compute the taint propagation paths and not just source-to-sink connections. This is a shorthand notation for -pr fast.");
        this.options.addOption(OPTION_LOG_SOURCES_SINKS, "logsourcesandsinks", false, "Write the discovered sources and sinks to the log output");
        this.options.addOption("mt", "maxthreadnum", true, "Limit the maximum number of threads to the given value");
        this.options.addOption(OPTION_ONE_COMPONENT, "onecomponentatatime", false, "Analyze one Android component at a time");
        this.options.addOption(OPTION_ONE_SOURCE, "onesourceatatime", false, "Analyze one source at a time");
        this.options.addOption(OPTION_SEQUENTIAL_PATHS, "sequentialpathprocessing", false, "Process the result paths sequentially instead of in parallel");
        this.options.addOption(OPTION_SINGLE_JOIN_POINT, "singlejoinpointabstraction", false, "Only use a single abstraction at join points, i.e., do not support multiple sources for one value");
        this.options.addOption(OPTION_MAX_CALLBACKS_COMPONENT, "maxcallbackspercomponent", true, "Eliminate Android components that have more than the given number of callbacks");
        this.options.addOption(OPTION_MAX_CALLBACKS_DEPTH, "maxcallbacksdepth", true, "Only analyze callback chains up to the given depth");
        this.options.addOption(OPTION_MERGE_DEX_FILES, "mergedexfiles", false, "Merge all dex files in the given APK file into one analysis target");
        this.options.addOption(OPTION_PATH_SPECIFIC_RESULTS, "pathspecificresults", false, "Report different results for same source/sink pairs if they differ in their propagation paths");
        this.options.addOption(OPTION_ICC_MODEL, "iccmodel", true, "File containing the inter-component data flow model (ICC model)");
        this.options.addOption(OPTION_ICC_NO_PURIFY, "noiccresultspurify", false, "Do not purify the ICC results, i.e., do not remove simple flows that also have a corresponding ICC flow");
        this.options.addOption(OPTION_CALLGRAPH_ALGO, "cgalgo", true, "Callgraph algorithm to use (AUTO, CHA, VTA, RTA, SPARK, GEOM)");
        this.options.addOption(OPTION_LAYOUT_MODE, "layoutmode", true, "Mode for considerung layout controls as sources (NONE, PWD, ALL)");
        this.options.addOption(OPTION_PATH_RECONSTRUCTION_ALGO, "pathalgo", true, "Use the specified algorithm for computing result paths (CONTEXTSENSITIVE, CONTEXTINSENSITIVE, SOURCESONLY)");
        this.options.addOption(OPTION_CALLBACK_ANALYZER, "callbackanalyzer", true, "Use the specified callback analyzer (DEFAULT, FAST)");
        this.options.addOption(OPTION_DATA_FLOW_SOLVER, "dataflowsolver", true, "Use the specified data flow solver (HEROS, CONTEXTFLOWSENSITIVE, FLOWINSENSITIVE)");
        this.options.addOption(OPTION_ALIAS_ALGO, "aliasalgo", true, "Use the specified aliasing algorithm (NONE, FLOWSENSITIVE, PTSBASED, LAZY)");
        this.options.addOption(OPTION_CODE_ELIMINATION_MODE, "codeelimination", true, "Use the specified code elimination algorithm (NONE, PROPAGATECONSTS, REMOVECODE)");
        this.options.addOption(OPTION_CALLBACK_SOURCE_MODE, "callbacksourcemode", true, "Use the specified mode for defining which callbacks introduce which sources (NONE, ALL, SOURCELIST)");
        this.options.addOption(OPTION_PATH_RECONSTRUCTION_MODE, "pathreconstructionmode", true, "Use the specified mode for reconstructing taint propagation paths (NONE, FAST, PRECISE).");
        this.options.addOption(OPTION_IMPLICIT_FLOW_MODE, "implicit", true, "Use the specified mode when processing implicit data flows (NONE, ARRAYONLY, ALL)");
        this.options.addOption(OPTION_OUTPUT_FASTDROID_FILE, "fastdroidoutput", true, "Output TXT file for the FastDroid discovered data flows");
        this.options.addOption(OPTION_LIMITED_ROUND, "limited", true, "The max round for the analysis of Fastdroid");
        this.options.addOption(OPTION_TAINT_METHOD_SUMMARY, XMLConstants.TREE_SUMMARY, true, "The taint summary of Fastdroid");
        this.options.addOption(OPTION_FLOW_SENSITIVITY, "flow-sensitivity", false, "The taint analysis of Fastdroid support flow-sensitive");
        this.options.addOption(OPTION_PATH_SENSITIVITY, "path-sensitivity", false, "The taint analysis of Fastdroid support path-sensitive");
        this.options.addOption(OPTION_FAST_MODE, "fast-mode", false, "The taint analysis of Fastdroid allows add same taint value in different context");
    }

    private TaintLauncher() {
        initializeCommandLineOptions();
    }
    public static void run_dex(String platforms,String classJson,String eastTaintWrapper,String sourceAndSinks,String callbacks,String outPut){
        try {
            InfoflowAndroidConfiguration config =  new InfoflowAndroidConfiguration();
            config.getAnalysisFileConfig().setAndroidPlatformDir(platforms);
//            config.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            config.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            config.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            config.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            config.getPathConfiguration().setMaxCallStackSize(-1);
            config.getPathConfiguration().setMaxPathLength(-1);
            TaintConfig fConfig = new TaintConfig();
//            fConfig.setApkPath(apk);
            fConfig.setLimitedRound(1000);
            fConfig.setFlowSen(true);
            fConfig.setPathSen(true);
            fConfig.setFastMode(false);
            fConfig.setClassJson(classJson);
            fConfig.setOutputFile(new File(outPut,"results.txt").getAbsolutePath());
            fConfig.setOutDir(outPut);
            fConfig.setSummary(eastTaintWrapper);
            fConfig.setSourceSinkFilePath(sourceAndSinks);
            fConfig.setCallbacks(callbacks);
            taintAnalyser = new TaintAnalyzer();
            taintAnalyser.initialize(fConfig);
            taintAnalyser.run_dex(config);
        } catch (Exception e2) {
            System.err.println(String.format("The FastDroid data flow analysis has failed. Error message: %s", e2.getMessage()));
            e2.printStackTrace();
        }
    }
    public static ArrayList<List> run(String apk, String platforms, String classJson, String eastTaintWrapper, String sourceAndSinks, String callbacks, String outPut){
        try {
            InfoflowAndroidConfiguration config =  new InfoflowAndroidConfiguration();
            config.getAnalysisFileConfig().setAndroidPlatformDir(platforms);
            config.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            config.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            config.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            config.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            config.getPathConfiguration().setMaxCallStackSize(-1);
            config.getPathConfiguration().setMaxPathLength(-1);
            TaintConfig fConfig = new TaintConfig();
            fConfig.setApkPath(apk);
            fConfig.setLimitedRound(1000);
            fConfig.setFlowSen(true);
            fConfig.setPathSen(true);
            fConfig.setFastMode(false);
            fConfig.setClassJson(classJson);
            fConfig.setOutputFile(new File(outPut,"results.txt").getAbsolutePath());
            fConfig.setOutDir(outPut);
            fConfig.setSummary(eastTaintWrapper);
            fConfig.setSourceSinkFilePath(sourceAndSinks);
            fConfig.setCallbacks(callbacks);
            taintAnalyser = new TaintAnalyzer();
            taintAnalyser.initialize(fConfig);
            ArrayList<List> taintFlows = taintAnalyser.my_run(config);
            return taintFlows;
        } catch (Exception e2) {
            System.err.println(String.format("The FastDroid data flow analysis has failed. Error message: %s", e2.getMessage()));
            e2.printStackTrace();
        }
        return null;
    }
    public static void run(String apk,String platforms,String eastTaintWrapper,String sourceAndSinks,String callbacks,String outPut){
        try {
            InfoflowAndroidConfiguration config =  new InfoflowAndroidConfiguration();
            config.getAnalysisFileConfig().setAndroidPlatformDir(platforms);
            config.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            config.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            config.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            config.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            config.getPathConfiguration().setMaxCallStackSize(-1);
            config.getPathConfiguration().setMaxPathLength(-1);
            TaintConfig fConfig = new TaintConfig();
            fConfig.setApkPath(apk);
            fConfig.setLimitedRound(1000);
            fConfig.setFlowSen(true);
            fConfig.setPathSen(true);
            fConfig.setFastMode(false);
            fConfig.setOutputFile(new File(outPut,"results.txt").getAbsolutePath());
            fConfig.setOutDir(outPut);
            fConfig.setSummary(eastTaintWrapper);
            fConfig.setSourceSinkFilePath(sourceAndSinks);
            fConfig.setCallbacks(callbacks);
            taintAnalyser = new TaintAnalyzer();
            taintAnalyser.initialize(fConfig);
            taintAnalyser.run(config);
        } catch (Exception e2) {
            System.err.println(String.format("The FastDroid data flow analysis has failed. Error message: %s", e2.getMessage()));
            e2.printStackTrace();
        }
    }
    public static void main(String[] args) throws Exception {
//        FastdroidLauncher fLauncher = new FastdroidLauncher();
//        fLauncher.run(args);
        try {
            String apk="C:\\Users\\77294\\Desktop\\fastdroid_test\\DroidBench3.0\\apk\\InterComponentCommunication\\ActivityCommunication6.apk";
            InfoflowAndroidConfiguration config =  new InfoflowAndroidConfiguration();
            config.getAnalysisFileConfig().setAndroidPlatformDir("C:\\Users\\77294\\AppData\\Local\\Android\\Sdk\\platforms");
            config.getAnalysisFileConfig().setTargetAPKFile(apk);
            // apk中的dex文件有对方法数量的限制导致实际app中往往是多dex，不作设置将仅分析classes.dex
            config.setMergeDexFiles(true);
            // 设置AccessPath长度限制，默认为5，设置负数表示不作限制，AccessPath会在后文解释
            config.getAccessPathConfiguration().setAccessPathLength(-1);
            // 设置Abstraction的path长度限制，设置负数表示不作限制，Abstraction会在后文解释
            config.getSolverConfiguration().setMaxAbstractionPathLength(-1);
            config.getPathConfiguration().setMaxCallStackSize(-1);
            config.getPathConfiguration().setMaxPathLength(-1);
            TaintConfig fConfig = new TaintConfig();
            fConfig.setApkPath(apk);
            fConfig.setLimitedRound(1000);
            fConfig.setFlowSen(false);
            fConfig.setPathSen(false);
            fConfig.setFastMode(false);
            fConfig.setClassJson("C:\\Users\\77294\\Desktop\\fastdroid_test\\output\\2\\de.ecspride\\class.json");
            fConfig.setOutputFile("C:\\Users\\77294\\Desktop\\fastdroid_test\\output\\2\\de.ecspride\\result2.txt");
            fConfig.setOutDir("C:\\Users\\77294\\Desktop\\fastdroid_test\\output\\2\\de.ecspride");
            fConfig.setSummary("D:\\github_project\\FastDroid-master\\Files\\EasyTaintWrapperSource.txt");
            fConfig.setSourceSinkFilePath("C:\\Users\\77294\\Desktop\\fastdroid_test\\source_sinks.txt");
            fConfig.setCallbacks("D:\\cert\\input\\callbacktest.txt");
            taintAnalyser = new TaintAnalyzer();
            taintAnalyser.initialize(fConfig);
            taintAnalyser.run(config);
        } catch (Exception e2) {
            System.err.println(String.format("The FastDroid data flow analysis has failed. Error message: %s", e2.getMessage()));
            e2.printStackTrace();
        }
    }
    private void run(String[] args) {
        HelpFormatter formatter = new HelpFormatter();
        if (args.length == 0) {
            formatter.printHelp("FastDroid [OPTIONS]", this.options);
            return;
        }
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(this.options, args);
            if (cmd.hasOption(LocationInfo.NA) || cmd.hasOption("help")) {
                formatter.printHelp("soot-infoflow-cmd [OPTIONS]", this.options);
                return;
            }
            String configFile = cmd.getOptionValue(OPTION_CONFIG_FILE);
            InfoflowAndroidConfiguration config = (configFile == null || configFile.isEmpty()) ? new InfoflowAndroidConfiguration() : loadConfigurationFile(configFile);
            if (config == null) {
                return;
            }
            parseCommandLineOptions(cmd, config);
            TaintConfig fConfig = new TaintConfig();
            fConfig.setApkPath(cmd.getOptionValue(OPTION_APK_FILE));
            if (cmd.hasOption(OPTION_LIMITED_ROUND)) {
                fConfig.setLimitedRound(Integer.parseInt(cmd.getOptionValue(OPTION_LIMITED_ROUND)));
            } else {
                fConfig.setLimitedRound(10);
            }
            if (cmd.hasOption(OPTION_FLOW_SENSITIVITY)) {
                fConfig.setFlowSen(true);
            } else {
                fConfig.setFlowSen(false);
            }
            if (cmd.hasOption(OPTION_PATH_SENSITIVITY)) {
                fConfig.setPathSen(true);
            } else {
                fConfig.setPathSen(false);
            }
            if (cmd.hasOption(OPTION_FAST_MODE)) {
                fConfig.setFastMode(true);
            } else {
                fConfig.setFastMode(false);
            }
            fConfig.setOutputFile(cmd.getOptionValue(OPTION_OUTPUT_FASTDROID_FILE));
            fConfig.setSummary(cmd.getOptionValue(OPTION_TAINT_METHOD_SUMMARY));
            fConfig.setSourceSinkFilePath(cmd.getOptionValue(OPTION_SOURCES_SINKS_FILE));
            taintAnalyser = new TaintAnalyzer();
            taintAnalyser.initialize(fConfig);
            taintAnalyser.run(config);
        } catch (ParseException e) {
            formatter.printHelp("FastDroid [OPTIONS]", this.options);
        } catch (Exception e2) {
            System.err.println(String.format("The FastDroid data flow analysis has failed. Error message: %s", e2.getMessage()));
            e2.printStackTrace();
        }
    }

    private static InfoflowConfiguration.CallgraphAlgorithm parseCallgraphAlgorithm(String algo) {
        if (algo.equalsIgnoreCase("AUTO")) {
            return InfoflowConfiguration.CallgraphAlgorithm.AutomaticSelection;
        }
        if (algo.equalsIgnoreCase("CHA")) {
            return InfoflowConfiguration.CallgraphAlgorithm.CHA;
        }
        if (algo.equalsIgnoreCase("VTA")) {
            return InfoflowConfiguration.CallgraphAlgorithm.VTA;
        }
        if (algo.equalsIgnoreCase("RTA")) {
            return InfoflowConfiguration.CallgraphAlgorithm.RTA;
        }
        if (algo.equalsIgnoreCase("SPARK")) {
            return InfoflowConfiguration.CallgraphAlgorithm.SPARK;
        }
        if (algo.equalsIgnoreCase("GEOM")) {
            return InfoflowConfiguration.CallgraphAlgorithm.GEOM;
        }
        System.err.println(String.format("Invalid callgraph algorithm: %s", algo));
        throw new AbortAnalysisException();
    }

    private static InfoflowAndroidConfiguration.LayoutMatchingMode parseLayoutMatchingMode(String layoutMode) {
        if (layoutMode.equalsIgnoreCase("NONE")) {
            return InfoflowAndroidConfiguration.LayoutMatchingMode.NoMatch;
        }
        if (layoutMode.equalsIgnoreCase("PWD")) {
            return InfoflowAndroidConfiguration.LayoutMatchingMode.MatchSensitiveOnly;
        }
        if (layoutMode.equalsIgnoreCase("ALL")) {
            return InfoflowAndroidConfiguration.LayoutMatchingMode.MatchAll;
        }
        System.err.println(String.format("Invalid layout matching mode: %s", layoutMode));
        throw new AbortAnalysisException();
    }

    private static InfoflowConfiguration.PathBuildingAlgorithm parsePathReconstructionAlgo(String pathAlgo) {
        if (pathAlgo.equalsIgnoreCase("CONTEXTSENSITIVE")) {
            return InfoflowConfiguration.PathBuildingAlgorithm.ContextSensitive;
        }
        if (pathAlgo.equalsIgnoreCase("CONTEXTINSENSITIVE")) {
            return InfoflowConfiguration.PathBuildingAlgorithm.ContextInsensitive;
        }
        if (pathAlgo.equalsIgnoreCase("SOURCESONLY")) {
            return InfoflowConfiguration.PathBuildingAlgorithm.ContextInsensitiveSourceFinder;
        }
        System.err.println(String.format("Invalid path reconstruction algorithm: %s", pathAlgo));
        throw new AbortAnalysisException();
    }

    private static InfoflowAndroidConfiguration.CallbackAnalyzer parseCallbackAnalyzer(String callbackAnalyzer) {
        if (callbackAnalyzer.equalsIgnoreCase(PropertyManager.DEFAULT_PROPERTY_READER_TOKEN)) {
            return InfoflowAndroidConfiguration.CallbackAnalyzer.Default;
        }
        if (callbackAnalyzer.equalsIgnoreCase("FAST")) {
            return InfoflowAndroidConfiguration.CallbackAnalyzer.Fast;
        }
        System.err.println(String.format("Invalid callback analysis algorithm: %s", callbackAnalyzer));
        throw new AbortAnalysisException();
    }

    private static InfoflowConfiguration.DataFlowSolver parseDataFlowSolver(String solver) {
        if (solver.equalsIgnoreCase("CONTEXTFLOWSENSITIVE")) {
            return InfoflowConfiguration.DataFlowSolver.ContextFlowSensitive;
        }
        if (solver.equalsIgnoreCase("FLOWINSENSITIVE")) {
            return InfoflowConfiguration.DataFlowSolver.FlowInsensitive;
        }
        System.err.println(String.format("Invalid data flow solver: %s", solver));
        throw new AbortAnalysisException();
    }

    private static InfoflowConfiguration.AliasingAlgorithm parseAliasAlgorithm(String aliasAlgo) {
        if (aliasAlgo.equalsIgnoreCase("NONE")) {

            return InfoflowConfiguration.AliasingAlgorithm.None;
        }
        if (aliasAlgo.equalsIgnoreCase("FLOWSENSITIVE")) {
            return InfoflowConfiguration.AliasingAlgorithm.FlowSensitive;
        }
        if (aliasAlgo.equalsIgnoreCase("PTSBASED")) {
            return InfoflowConfiguration.AliasingAlgorithm.PtsBased;
        }
        if (aliasAlgo.equalsIgnoreCase("LAZY")) {
            return InfoflowConfiguration.AliasingAlgorithm.Lazy;
        }
        System.err.println(String.format("Invalid aliasing algorithm: %s", aliasAlgo));
        throw new AbortAnalysisException();
    }

    private static InfoflowConfiguration.CodeEliminationMode parseCodeEliminationMode(String eliminationMode) {
        if (eliminationMode.equalsIgnoreCase("NONE")) {
            return InfoflowConfiguration.CodeEliminationMode.NoCodeElimination;
        }
        if (eliminationMode.equalsIgnoreCase("PROPAGATECONSTS")) {
            return InfoflowConfiguration.CodeEliminationMode.PropagateConstants;
        }
        if (eliminationMode.equalsIgnoreCase("REMOVECODE")) {
            return InfoflowConfiguration.CodeEliminationMode.RemoveSideEffectFreeCode;
        }
        System.err.println(String.format("Invalid code elimination mode: %s", eliminationMode));
        throw new AbortAnalysisException();
    }

    private static InfoflowAndroidConfiguration.CallbackSourceMode parseCallbackSourceMode(String callbackMode) {
        if (callbackMode.equalsIgnoreCase("NONE")) {
            return InfoflowAndroidConfiguration.CallbackSourceMode.NoParametersAsSources;
        }
        if (callbackMode.equalsIgnoreCase("ALL")) {
            return InfoflowAndroidConfiguration.CallbackSourceMode.AllParametersAsSources;
        }
        if (callbackMode.equalsIgnoreCase("SOURCELIST")) {
            return InfoflowAndroidConfiguration.CallbackSourceMode.SourceListOnly;
        }
        System.err.println(String.format("Invalid callback source mode: %s", callbackMode));
        throw new AbortAnalysisException();
    }

    private static InfoflowConfiguration.PathReconstructionMode parsePathReconstructionMode(String pathReconstructionMode) {
        if (pathReconstructionMode.equalsIgnoreCase("NONE")) {
            return InfoflowConfiguration.PathReconstructionMode.NoPaths;
        }
        if (pathReconstructionMode.equalsIgnoreCase("FAST")) {
            return InfoflowConfiguration.PathReconstructionMode.Fast;
        }
        if (pathReconstructionMode.equalsIgnoreCase("PRECISE")) {
            return InfoflowConfiguration.PathReconstructionMode.Precise;
        }
        System.err.println(String.format("Invalid path reconstruction mode: %s", pathReconstructionMode));
        throw new AbortAnalysisException();
    }

    private static InfoflowConfiguration.ImplicitFlowMode parseImplicitFlowMode(String implicitFlowMode) {
        if (implicitFlowMode.equalsIgnoreCase("NONE")) {
            return InfoflowConfiguration.ImplicitFlowMode.NoImplicitFlows;
        }
        if (implicitFlowMode.equalsIgnoreCase("ARRAYONLY")) {
            return InfoflowConfiguration.ImplicitFlowMode.ArrayAccesses;
        }
        if (implicitFlowMode.equalsIgnoreCase("ALL")) {
            return InfoflowConfiguration.ImplicitFlowMode.AllImplicitFlows;
        }
        System.err.println(String.format("Invalid implicit flow mode: %s", implicitFlowMode));
        throw new AbortAnalysisException();
    }

    private void parseCommandLineOptions(CommandLine cmd, InfoflowAndroidConfiguration config) {
        String apkFile = cmd.getOptionValue(OPTION_APK_FILE);
        if (apkFile != null && !apkFile.isEmpty()) {
            config.getAnalysisFileConfig().setTargetAPKFile(apkFile);
        }
        String platformsDir = cmd.getOptionValue(OPTION_PLATFORMS_DIR);
        if (platformsDir != null && !platformsDir.isEmpty()) {
            config.getAnalysisFileConfig().setAndroidPlatformDir(platformsDir);
        }
        String sourcesSinks = cmd.getOptionValue(OPTION_SOURCES_SINKS_FILE);
        if (sourcesSinks != null && !sourcesSinks.isEmpty()) {
            config.getAnalysisFileConfig().setSourceSinkFile(sourcesSinks);
        }
        String outputFile = cmd.getOptionValue(OPTION_OUTPUT_FILE);
        if (outputFile != null && !outputFile.isEmpty()) {
            config.getAnalysisFileConfig().setOutputFile(outputFile);
        }
        int timeout = getIntOption(cmd, OPTION_TIMEOUT);
        config.setDataFlowTimeout(timeout);
        int timeout2 = getIntOption(cmd, OPTION_CALLBACK_TIMEOUT);
        config.getCallbackConfig().setCallbackAnalysisTimeout(timeout2);
        int timeout3 = getIntOption(cmd, OPTION_RESULT_TIMEOUT);
        config.getPathConfiguration().setPathReconstructionTimeout(timeout3);

        //设置模式
        config.setStaticFieldTrackingMode(InfoflowConfiguration.StaticFieldTrackingMode.ContextFlowSensitive);
        if (cmd.hasOption(OPTION_NO_CALLBACK_ANALYSIS)) {
            config.getCallbackConfig().setEnableCallbacks(false);
        }
        if (cmd.hasOption(OPTION_NO_EXCEPTIONAL_FLOWS)) {
            config.setEnableExceptionTracking(false);
        }
        if (cmd.hasOption(OPTION_NO_TYPE_CHECKING)) {
            config.setEnableTypeChecking(false);
        }
        if (cmd.hasOption(OPTION_REFLECTION)) {
            config.setEnableReflection(true);
        }
        int aplength = getIntOption(cmd, OPTION_ACCESS_PATH_LENGTH);
        if (aplength >= 0) {
            config.getAccessPathConfiguration().setAccessPathLength(aplength);
        }
        if (cmd.hasOption(OPTION_FLOW_INSENSITIVE_ALIASING)) {
            config.setFlowSensitiveAliasing(false);
        }
        if (cmd.hasOption(OPTION_COMPUTE_PATHS)) {
            config.getPathConfiguration().setPathReconstructionMode(InfoflowConfiguration.PathReconstructionMode.Fast);
        }
        if (cmd.hasOption(OPTION_ONE_SOURCE)) {
            config.setOneSourceAtATime(true);
        }
        if (cmd.hasOption(OPTION_ONE_COMPONENT)) {
            config.setOneComponentAtATime(true);
        }
        if (cmd.hasOption(OPTION_SEQUENTIAL_PATHS)) {
            config.getPathConfiguration().setSequentialPathProcessing(true);
        }
        if (cmd.hasOption(OPTION_LOG_SOURCES_SINKS)) {
            config.setLogSourcesAndSinks(true);
        }
        if (cmd.hasOption(OPTION_MERGE_DEX_FILES)) {
            config.setMergeDexFiles(true);
        }
        if (cmd.hasOption(OPTION_PATH_SPECIFIC_RESULTS)) {
            config.setPathAgnosticResults(false);
        }
        if (cmd.hasOption(OPTION_SINGLE_JOIN_POINT)) {
            config.getSolverConfiguration().setSingleJoinPointAbstraction(true);
        }
        int maxCallbacks = getIntOption(cmd, OPTION_MAX_CALLBACKS_COMPONENT);
        if (maxCallbacks >= 0) {
            config.getCallbackConfig().setMaxCallbacksPerComponent(maxCallbacks);
        }
        int maxDepth = getIntOption(cmd, OPTION_MAX_CALLBACKS_DEPTH);
        if (maxDepth >= 0) {
            config.getCallbackConfig().setMaxAnalysisCallbackDepth(maxDepth);
        }
        if (cmd.hasOption(OPTION_ICC_NO_PURIFY)) {
            config.getIccConfig().setIccResultsPurify(false);
        }
        String iccModel = cmd.getOptionValue(OPTION_ICC_MODEL);
        if (iccModel != null && !iccModel.isEmpty()) {
            config.getIccConfig().setIccModel(iccModel);
        }
        String cgalgo = cmd.getOptionValue(OPTION_CALLGRAPH_ALGO);
        if (cgalgo != null && !cgalgo.isEmpty()) {
            config.setCallgraphAlgorithm(parseCallgraphAlgorithm(cgalgo));
        }
        String layoutMode = cmd.getOptionValue(OPTION_LAYOUT_MODE);
        if (layoutMode != null && !layoutMode.isEmpty()) {
            config.getSourceSinkConfig().setLayoutMatchingMode(parseLayoutMatchingMode(layoutMode));
        }
        String pathAlgo = cmd.getOptionValue(OPTION_PATH_RECONSTRUCTION_ALGO);
        if (pathAlgo != null && !pathAlgo.isEmpty()) {
            config.getPathConfiguration().setPathBuildingAlgorithm(parsePathReconstructionAlgo(pathAlgo));
        }
        String callbackAnalyzer = cmd.getOptionValue(OPTION_CALLBACK_ANALYZER);
        if (callbackAnalyzer != null && !callbackAnalyzer.isEmpty()) {
            config.getCallbackConfig().setCallbackAnalyzer(parseCallbackAnalyzer(callbackAnalyzer));
        }
        String solver = cmd.getOptionValue(OPTION_DATA_FLOW_SOLVER);
        if (solver != null && !solver.isEmpty()) {
            config.getSolverConfiguration().setDataFlowSolver(parseDataFlowSolver(solver));
        }
        String aliasAlgo = cmd.getOptionValue(OPTION_ALIAS_ALGO);
        if (aliasAlgo != null && !aliasAlgo.isEmpty()) {
            config.setAliasingAlgorithm(parseAliasAlgorithm(aliasAlgo));
        }
        String eliminationMode = cmd.getOptionValue(OPTION_CODE_ELIMINATION_MODE);
        if (eliminationMode != null && !eliminationMode.isEmpty()) {
            config.setCodeEliminationMode(parseCodeEliminationMode(eliminationMode));
        }
        String callbackMode = cmd.getOptionValue(OPTION_CALLBACK_SOURCE_MODE);
        if (callbackMode != null && !callbackMode.isEmpty()) {
            config.getSourceSinkConfig().setCallbackSourceMode(parseCallbackSourceMode(callbackMode));
        }
        String pathMode = cmd.getOptionValue(OPTION_PATH_RECONSTRUCTION_MODE);
        if (pathMode != null && !pathMode.isEmpty()) {
            config.getPathConfiguration().setPathReconstructionMode(parsePathReconstructionMode(pathMode));
        }
        String implicitMode = cmd.getOptionValue(OPTION_IMPLICIT_FLOW_MODE);
        if (implicitMode != null && !implicitMode.isEmpty()) {
            config.setImplicitFlowMode(parseImplicitFlowMode(implicitMode));
        }
    }

    private int getIntOption(CommandLine cmd, String option) {
        String str = cmd.getOptionValue(option);
        if (str == null || str.isEmpty()) {
            return -1;
        }
        return Integer.parseInt(str);
    }

    private InfoflowAndroidConfiguration loadConfigurationFile(String configFile) {
        try {
            InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
            XMLConfigurationParser.fromFile(configFile).parse(config);
            return config;
        } catch (IOException e) {
            System.err.println("Could not parse configuration file: " + e.getMessage());
            return null;
        }
    }
}
