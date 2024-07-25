package secondstage.taintanalysis.analyzer;

import org.apache.commons.io.IOUtils;
import secondstage.taintanalysis.taint.FlowResult;
import secondstage.taintanalysis.taint.TaintValue;
import secondstage.taintanalysis.taint.TaintResult;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;


public class FileOutput {
    FileWriter filewriter;
    String apkName;
    String apkPath;

    public FileOutput(String apkPath, String apkName, String filePath) {
        try {
            this.filewriter = new FileWriter(filePath, true);
        } catch (IOException e) {
            System.out.println("写入失败");
        }
        this.apkName = apkName;
        this.apkPath = apkPath;
    }

    public void printName() {
        try {
            this.filewriter.write("Analyse:  !N<" + this.apkName + ">N!  !!!!!!!!!!\r\n");
            this.filewriter.write("Analyse:  !P<" + this.apkPath + ">P!  !!!!!!!!!!\r\n");
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }

    public void printCFGTime(double time) {
        try {
            this.filewriter.write("preprocess and CFG Construction have run for !C<" + time + ">C! seconds\r\n");
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }

    public void printNum(int ClassNum, int MethodNum, int StateMNum) {
        try {
            this.filewriter.write("Totally analysis:" + ClassNum + " Classes，" + MethodNum + " Methods，" + StateMNum + " Statements\r\n");
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }

    public void printTaintNum(int index) {
        try {
            this.filewriter.write("TaintFlow " + index + " exist!\r\n");
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }

    public void printMayTaint(TaintValue m) {
        try {
            this.filewriter.write(m.getSL().toString() + IOUtils.LINE_SEPARATOR_WINDOWS);
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }

    public void printSourceandSink(TaintResult result) {
        int FlowIndex = 0;
        Iterator<FlowResult> it = result.taintFlowsResult.iterator();
        while (it.hasNext()) {
            FlowResult Flow = it.next();
            FlowIndex++;
            try {
                this.filewriter.write("TaintFlow " + FlowIndex + IOUtils.LINE_SEPARATOR_WINDOWS);
                this.filewriter.write("Source--->");
                this.filewriter.write(Flow.getFlow().get(0).toString() + IOUtils.LINE_SEPARATOR_WINDOWS);
                this.filewriter.write("Sink--->");
                this.filewriter.write(Flow.getFlow().get(Flow.getFlow().size() - 1).toString() + IOUtils.LINE_SEPARATOR_WINDOWS);
            } catch (IOException e) {
                System.out.println("写入失败");
            }
        }
    }

    public void printDetail(TaintResult result) {
        int FlowIndex = 0;
        Iterator<FlowResult> it = result.taintFlowsResult.iterator();
        while (it.hasNext()) {
            FlowResult Flow = it.next();
            FlowIndex++;
            try {
                this.filewriter.write("TaintFlow " + FlowIndex + IOUtils.LINE_SEPARATOR_WINDOWS);
            } catch (IOException e) {
                System.out.println("写入失败");
            }
            Iterator<TaintValue> it2 = Flow.getFlow().iterator();
            while (it2.hasNext()) {
                TaintValue Value = it2.next();
                try {
                    this.filewriter.write(Value.toFileString() + IOUtils.LINE_SEPARATOR_WINDOWS);
                } catch (IOException e2) {
                    System.out.println("写入失败");
                }
            }
        }
        int FlowIndex2 = 0;
        Iterator<FlowResult> it3 = result.mayFlowsResult.iterator();
        while (it3.hasNext()) {
            FlowResult Flow2 = it3.next();
            FlowIndex2++;
            try {
                this.filewriter.write("MayTaintFlow " + FlowIndex2 + IOUtils.LINE_SEPARATOR_WINDOWS);
            } catch (IOException e3) {
                System.out.println("写入失败");
            }
            Iterator<TaintValue> it4 = Flow2.getFlow().iterator();
            while (it4.hasNext()) {
                TaintValue Value2 = it4.next();
                try {
                    this.filewriter.write(Value2.toFileString() + IOUtils.LINE_SEPARATOR_WINDOWS);
                } catch (IOException e4) {
                    System.out.println("写入失败");
                }
            }
        }
    }

    public void printFinal(EfficiencyResult efficiencyResult, int taintflownum, int mtaintF) {
        try {
            this.filewriter.write("Apk Size is  !K<" + efficiencyResult.apkSize + ">K! KB\r\n");
            this.filewriter.write("code size is  !S<" + efficiencyResult.codeSize + ">S! lines\r\n");
            this.filewriter.write("CFG construction has run for !C<" + efficiencyResult.timeOfCreateCFG + ">C! seconds\r\n");
            this.filewriter.write("Fastdroid analysis has run for !R<" + efficiencyResult.timeOfFastDroidTaintAnalize + ">R! seconds\r\n");
            this.filewriter.write("TaintFlow totally Number is  !T<" + taintflownum + ">T!\r\n");
            this.filewriter.write("MayTaintFlow totally Number is  !M<" + mtaintF + ">M!\r\n");
            this.filewriter.write("--------------------------FINISH--------------------------------------\r\n");
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }

    public void close() {
        try {
            this.filewriter.close();
        } catch (IOException e) {
            System.out.println("写入失败");
        }
    }
}
