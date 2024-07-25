package secondstage.taintanalysis.taint;

import soot.Unit;


public class StmLocation {
    private String SC;
    private String SMsig;
    private int ST;
    private Unit Statement;

    public String getSC() {
        return this.SC;
    }

    public String getSM() {
        return this.SMsig;
    }

    public int getST() {
        return this.ST;
    }

    public Unit getStatement() {
        return this.Statement;
    }

    public StmLocation(String SC, String SM, int ST, Unit Statement) {
        this.SC = SC;
        this.SMsig = SM;
        this.ST = ST;
        this.Statement = Statement;
    }

    public int hashCode() {
        int result = (31 * 1) + (this.SC == null ? 0 : this.SC.hashCode());
        return (31 * ((31 * ((31 * result) + (this.SMsig == null ? 0 : this.SMsig.hashCode()))) + this.ST)) + (this.Statement == null ? 0 : this.Statement.hashCode());
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        StmLocation other = (StmLocation) obj;
        if (this.SC == null) {
            if (other.SC != null) {
                return false;
            }
        } else if (!this.SC.equals(other.SC)) {
            return false;
        }
        if (this.SMsig == null) {
            if (other.SMsig != null) {
                return false;
            }
        } else if (!this.SMsig.equals(other.SMsig)) {
            return false;
        }
        if (this.ST != other.ST) {
            return false;
        }
        if (this.Statement == null) {
            if (other.Statement != null) {
                return false;
            }
            return true;
        } else if (!this.Statement.toString().equals(other.Statement.toString())) {
            return false;
        } else {
            return true;
        }
    }

    public String toString() {
        return "SL [" + this.SC + ", " + this.SMsig + ", No.=" + this.ST + ", State=" + this.Statement + "]";
    }
}
