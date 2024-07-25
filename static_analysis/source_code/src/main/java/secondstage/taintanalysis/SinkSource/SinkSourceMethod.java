package secondstage.taintanalysis.SinkSource;

import org.slf4j.Marker;
import soot.SootMethod;
import soot.jimple.InvokeExpr;

import java.util.ArrayList;
import java.util.Iterator;


public class SinkSourceMethod {
    private String Classname;
    private int paranum;
    private String returnType = null;
    private String Methodname = null;
    private ArrayList<String> paraType = null;

    public boolean matchInvokeEx(InvokeExpr iE) {
        if (iE.getMethod().getDeclaringClass().getName().equals(this.Classname) && iE.getMethod().getName().equals(this.Methodname) && iE.getMethod().getParameterCount() == this.paranum) {
            return true;
        }
        return false;
    }

    public boolean matchSootMethod(SootMethod sM) {
        if (sM.getDeclaringClass().getName().equals(this.Classname) && sM.getName().equals(this.Methodname) && sM.getParameterCount() == this.paranum) {
            return true;
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void print() {
        String temp = "";
        if (this.paranum > 0) {
            Iterator<String> iter = this.paraType.iterator();
            while (iter.hasNext()) {
                temp = temp + iter.next().toString() + ",";
            }
        }
        System.err.println(this.Classname + Marker.ANY_NON_NULL_MARKER + this.returnType + Marker.ANY_NON_NULL_MARKER + this.Methodname + Marker.ANY_NON_NULL_MARKER + temp + this.paranum);
    }

    public String getReturnType() {
        return this.returnType;
    }

    public void setReturnType(String returnType) {
        this.returnType = returnType;
    }

    public String getMethodname() {
        return this.Methodname;
    }

    public void setMethodname(String methodname) {
        this.Methodname = methodname;
    }

    public ArrayList<String> getParaType() {
        return this.paraType;
    }

    public void setParaType(ArrayList<String> paraType) {
        this.paraType = paraType;
    }

    public int getParanum() {
        return this.paranum;
    }

    public void setParanum(int paranum) {
        this.paranum = paranum;
    }

    public String getClassname() {
        return this.Classname;
    }

    public void setClassname(String classname) {
        this.Classname = classname;
    }
}
