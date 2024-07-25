package secondstage.taintanalysis.taint;

import soot.SootClass;
import soot.SootMethod;


public class Context {
    SootClass sClass;
    SootMethod sMethod;
    StmLocation location;

    public Context(SootClass sClass, SootMethod sootMethod, StmLocation location) {
        this.sClass = sClass;
        this.sMethod = sootMethod;
        this.location = location;
    }

    public SootClass getsClass() {
        return this.sClass;
    }

    public SootMethod getsMethod() {
        return this.sMethod;
    }

    public StmLocation getLocation() {
        return this.location;
    }

    public boolean inSameMethod(Context other) {
        if (this.sClass.getName().equals(other.sClass.getName()) && this.sMethod.getName().equals(other.sMethod.getName())) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        int result = (31 * 1) + (this.location == null ? 0 : this.location.hashCode());
        return (31 * ((31 * result) + (this.sClass == null ? 0 : this.sClass.getName().hashCode()))) + (this.sMethod == null ? 0 : this.sMethod.getName().hashCode());
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Context other = (Context) obj;
        if (this.location == null) {
            if (other.location != null) {
                return false;
            }
        } else if (!this.location.equals(other.location)) {
            return false;
        }
        if (this.sClass == null) {
            if (other.sClass != null) {
                return false;
            }
        } else if (!this.sClass.getName().equals(other.sClass.getName())) {
            return false;
        }
        if (this.sMethod == null) {
            if (other.sMethod != null) {
                return false;
            }
            return true;
        } else if (!this.sMethod.getName().equals(other.sMethod.getName())) {
            return false;
        } else {
            return true;
        }
    }

    public String toString() {
        return "Context [sClass=" + this.sClass + ", sootMethod=" + this.sMethod + ", location=" + this.location + "]";
    }
}
