package secondstage.taintanalysis.SinkSource;

import soot.SootMethod;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;


public class SinkSourceBuilder {
    private ArrayList<SinkSourceMethod> SinkSet;
    private ArrayList<SinkSourceMethod> SourceSet;
    private BufferedReader in;
    private BufferedReader sinkIn;
    private BufferedReader sourceIn;
    private String str;

    public ArrayList<SinkSourceMethod> getSinkSet() {
        return this.SinkSet;
    }

    public ArrayList<SinkSourceMethod> getSourceSet() {
        return this.SourceSet;
    }

    public boolean matchSink(SootMethod sMethod) {
        Iterator<SinkSourceMethod> it = this.SinkSet.iterator();
        while (it.hasNext()) {
            SinkSourceMethod sinkM = it.next();
            if (sinkM.matchSootMethod(sMethod)) {
                return true;
            }
        }
        return false;
    }

    public boolean matchSource(SootMethod sMethod) {
        Iterator<SinkSourceMethod> it = this.SourceSet.iterator();
        while (it.hasNext()) {
            SinkSourceMethod sourceM = it.next();
            if (sourceM.matchSootMethod(sMethod)) {
                return true;
            }
        }
        return false;
    }

    public SinkSourceBuilder(String FileLoc) {
        try {
            this.in = new BufferedReader(new FileReader(FileLoc));
        } catch (FileNotFoundException e) {
            System.err.println("Flie not found");
        }
        this.str = "";
        this.SourceSet = new ArrayList<>();
        this.SinkSet = new ArrayList<>();
    }

    public SinkSourceBuilder(String SinkFLoc, String SourceFLoc) {
        try {
            this.sinkIn = new BufferedReader(new FileReader(SinkFLoc));
        } catch (FileNotFoundException e) {
            System.err.println("Flie not found");
        }
        try {
            this.sourceIn = new BufferedReader(new FileReader(SourceFLoc));
        } catch (FileNotFoundException e2) {
            System.err.println("Flie not found");
        }
        this.str = "";
        this.SourceSet = new ArrayList<>();
        this.SinkSet = new ArrayList<>();
    }

    public void print() {
        Iterator<SinkSourceMethod> iter = this.SourceSet.iterator();
        while (iter.hasNext()) {
            iter.next().print();
        }
        Iterator<SinkSourceMethod> iter2 = this.SinkSet.iterator();
        while (iter2.hasNext()) {
            iter2.next().print();
        }
    }

    public void BuildSink() {
        while (true) {
            try {
                String line = this.sinkIn.readLine();
                if (line != null) {
                    if (!line.startsWith("%")) {
                        int j1 = line.indexOf("<");
                        int m1 = line.indexOf(":");
                        int k1 = line.indexOf("(");
                        int k2 = line.indexOf(")");
                        SinkSourceMethod ss = new SinkSourceMethod();
                        if (j1 + 1 < m1) {
                            ss.setClassname(line.substring(j1 + 1, m1));
                        }
                        new String();
                        if (m1 + 2 < k1 && line.substring(m1 + 2, k1).contains(" ")) {
                            String temp1 = line.substring(m1 + 2, k1);
                            int t = temp1.indexOf(" ");
                            int tl = temp1.length();
                            ss.setReturnType(temp1.substring(0, t));
                            ss.setMethodname(temp1.substring(t + 1, tl));
                        }
                        new String();
                        if (k1 + 1 < k2) {
                            String temp2 = line.substring(k1 + 1, k2);
                            ArrayList<String> para = new ArrayList<>();
                            int num = 1;
                            while (temp2.indexOf(",") > 0) {
                                int x = temp2.indexOf(",");
                                num++;
                                para.add(temp2.substring(0, x));
                                temp2 = temp2.substring(x + 1, temp2.length());
                            }
                            ss.setParanum(num);
                            para.add(temp2);
                            ss.setParaType(para);
                        }
                        this.SinkSet.add(ss);
                    }
                } else {
                    return;
                }
            } catch (IOException e) {
                System.err.println("File IO err");
                return;
            }
        }
    }

    public void BuildSource() {
        while (true) {
            try {
                String line = this.sourceIn.readLine();
                if (line != null) {
                    if (!line.startsWith("%")) {
                        int j1 = line.indexOf("<");
                        int m1 = line.indexOf(":");
                        int k1 = line.indexOf("(");
                        int k2 = line.indexOf(")");
                        SinkSourceMethod ss = new SinkSourceMethod();
                        if (j1 + 1 < m1) {
                            ss.setClassname(line.substring(j1 + 1, m1));
                        }
                        new String();
                        if (m1 + 2 < k1 && line.substring(m1 + 2, k1).contains(" ")) {
                            String temp1 = line.substring(m1 + 2, k1);
                            int t = temp1.indexOf(" ");
                            int tl = temp1.length();
                            ss.setReturnType(temp1.substring(0, t));
                            ss.setMethodname(temp1.substring(t + 1, tl));
                        }
                        new String();
                        if (k1 + 1 < k2) {
                            String temp2 = line.substring(k1 + 1, k2);
                            ArrayList<String> para = new ArrayList<>();
                            int num = 1;
                            while (temp2.indexOf(",") > 0) {
                                int x = temp2.indexOf(",");
                                num++;
                                para.add(temp2.substring(0, x));
                                temp2 = temp2.substring(x + 1, temp2.length());
                            }
                            ss.setParanum(num);
                            para.add(temp2);
                            ss.setParaType(para);
                        }
                        this.SourceSet.add(ss);
                    }
                } else {
                    return;
                }
            } catch (IOException e) {
                System.err.println("File IO err");
                return;
            }
        }
    }

    public void Build() {
        while (true) {
            try {
                String line = this.in.readLine();
                if (line != null) {
                    if (!line.startsWith("%")) {
                        if (line.contains("_SOURCE_")) {
                            int j1 = line.indexOf("<");
                            int m1 = line.indexOf(":");
                            int k1 = line.indexOf("(");
                            int k2 = line.indexOf(")");
                            SinkSourceMethod ss = new SinkSourceMethod();
                            if (j1 + 1 < m1) {
                                ss.setClassname(line.substring(j1 + 1, m1));
                            }
                            new String();
                            if (m1 + 2 < k1 && line.substring(m1 + 2, k1).contains(" ")) {
                                String temp1 = line.substring(m1 + 2, k1);
                                int t = temp1.indexOf(" ");
                                int tl = temp1.length();
                                ss.setReturnType(temp1.substring(0, t));
                                ss.setMethodname(temp1.substring(t + 1, tl));
                            }
                            new String();
                            if (k1 + 1 < k2) {
                                String temp2 = line.substring(k1 + 1, k2);
                                ArrayList<String> para = new ArrayList<>();
                                int num = 1;
                                while (temp2.indexOf(",") > 0) {
                                    int x = temp2.indexOf(",");
                                    num++;
                                    para.add(temp2.substring(0, x));
                                    temp2 = temp2.substring(x + 1, temp2.length());
                                }
                                ss.setParanum(num);
                                para.add(temp2);
                                ss.setParaType(para);
                            }
                            this.SourceSet.add(ss);
                        } else if (line.contains("_SINK_")) {
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
                            this.SinkSet.add(ss2);
                        }
                    }
                } else {
                    return;
                }
            } catch (IOException e) {
                System.err.println("File IO err");
                return;
            }
        }
    }
}
