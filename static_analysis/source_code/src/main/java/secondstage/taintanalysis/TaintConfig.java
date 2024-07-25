package secondstage.taintanalysis;


public class TaintConfig {
    private String ApkPath = null;
    private String ApkName = null;
    private String outputFile = null;
    private int limitedRound = 10;
    private String Summary = null;

    public String getCallbacks() {
        return callbacks;
    }

    public void setCallbacks(String callbacks) {
        this.callbacks = callbacks;
    }

    private String callbacks;

    public String getClassJson() {
        return classJson;
    }

    public void setClassJson(String classJson) {
        this.classJson = classJson;
    }

    private String classJson=null;

    public String getOutDir() {
        return outDir;
    }

    public void setOutDir(String outDir) {
        this.outDir = outDir;
    }

    private String outDir=null;

    private String sourceSinkFilePath = null;
    private boolean FlowSen = true;
    private boolean PathSen = false;
    private boolean FastMode = false;

    public boolean isFastMode() {
        return this.FastMode;
    }

    public void setFastMode(boolean fastMode) {
        this.FastMode = fastMode;
    }

    public boolean isFlowSen() {
        return this.FlowSen;
    }

    public void setFlowSen(boolean flowSen) {
        this.FlowSen = flowSen;
    }

    public boolean isPathSen() {
        return this.PathSen;
    }

    public void setPathSen(boolean pathSen) {
        this.PathSen = pathSen;
    }

    public String getApkName() {
        return this.ApkName;
    }

    public void setApkName(String apkName) {
        this.ApkName = apkName;
    }

    public String getSourceSinkFilePath() {
        return this.sourceSinkFilePath;
    }

    public void setSourceSinkFilePath(String sourceSinkFilePath) {
        this.sourceSinkFilePath = sourceSinkFilePath;
    }

    public String getApkPath() {
        return this.ApkPath;
    }

    public void setApkPath(String apkPath) {
        this.ApkPath = apkPath;
        int posit = apkPath.lastIndexOf("/");
        this.ApkName = apkPath.substring(posit + 1);
    }

    public String getOutputFile() {
        return this.outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public int getLimitedRound() {
        return this.limitedRound;
    }

    public void setLimitedRound(int limitedRound) {
        this.limitedRound = limitedRound;
    }

    public String getSummary() {
        return this.Summary;
    }

    public void setSummary(String summary) {
        this.Summary = summary;
    }
}
