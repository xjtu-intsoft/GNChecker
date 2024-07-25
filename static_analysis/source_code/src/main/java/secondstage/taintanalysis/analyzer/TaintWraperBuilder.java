package secondstage.taintanalysis.analyzer;

import soot.SootClass;
import soot.SootMethod;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;


public class TaintWraperBuilder {
    public ArrayList<TMSummary> TMSummaries;
    private BufferedReader in;
    private String str;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TaintWraperBuilder(String FileLoc) {
        try {
            this.in = new BufferedReader(new FileReader(FileLoc));
        } catch (FileNotFoundException e) {
            System.err.println("Flie not found");
        }
        this.str = "";
        this.TMSummaries = new ArrayList<>();
    }

    public boolean hasMethod(SootClass sc, SootMethod sm) {
        Iterator<TMSummary> it = this.TMSummaries.iterator();
        while (it.hasNext()) {
            TMSummary TM = it.next();
            if (sc.getName().equals(TM.getClassname()) && sm.getName().equals(TM.getMethodname()) && sm.getParameterCount() == TM.getParanum()) {
                return true;
            }
        }
        return false;
    }

    public void print() {
        Iterator<TMSummary> it = this.TMSummaries.iterator();
        while (it.hasNext()) {
            TMSummary t = it.next();
            t.print();
        }
    }

    public void Build() {
        while (true) {
            try {
                String line = this.in.readLine();
                if (line != null) {
                    if (!line.startsWith("~") && line.contains("<")) {
                        int j1 = line.indexOf("<");
                        int m1 = line.indexOf(":");
                        int k1 = line.indexOf("(");
                        int k2 = line.indexOf(")");
                        TMSummary tms = new TMSummary();
                        if (j1 + 1 < m1) {
                            tms.setClassname(line.substring(j1 + 1, m1));
                        }
                        new String();
                        if (m1 + 2 < k1 && line.substring(m1 + 2, k1).contains(" ")) {
                            String temp1 = line.substring(m1 + 2, k1);
                            int t = temp1.indexOf(" ");
                            int tl = temp1.length();
                            tms.setReturnType(temp1.substring(0, t));
                            tms.setMethodname(temp1.substring(t + 1, tl));
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
                            tms.setParanum(num);
                            para.add(temp2);
                            tms.setParaType(para);
                        }
                        this.TMSummaries.add(tms);
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
