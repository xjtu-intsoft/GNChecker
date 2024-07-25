package secondstage.taintanalysis.analyzer.shortcut;

import org.apache.commons.cli.HelpFormatter;
import secondstage.taintanalysis.taint.StmLocation;

import java.util.HashSet;


public class Path {
    protected String pathString;
    protected HashSet<StmLocation> cleanAliasList;

    public Path(Integer index) {
        this.pathString = null;
        this.pathString = index.toString();
        this.cleanAliasList = new HashSet<>();
    }

    public Path() {
        this.pathString = null;
        this.pathString = "";
        this.cleanAliasList = null;
    }

    public Path(Path path1, HashSet<StmLocation> clean) {
        this.pathString = null;
        this.pathString = new String(path1.pathString);
        if (clean != null) {
            this.cleanAliasList = new HashSet<>(clean);
        } else {
            this.cleanAliasList = null;
        }
    }

    public Path(Path path1) {
        this.pathString = null;
        this.pathString = new String(path1.pathString);
        this.cleanAliasList = null;
    }

    public String getPathString() {
        return this.pathString;
    }

    public HashSet<StmLocation> getCleanAliasList() {
        return this.cleanAliasList;
    }

    public void add(int index) {
        this.pathString += HelpFormatter.DEFAULT_OPT_PREFIX + index;
    }

    public void addSink() {
        this.pathString += "-Sink";
    }

    public void addMay() {
        this.pathString += "-May";
    }

    public void cut(int index) {
        this.pathString += "x" + index;
    }

    public int hashCode() {
        int result = (31 * 1) + (this.pathString == null ? 0 : this.pathString.hashCode());
        return result;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Path other = (Path) obj;
        if (this.pathString == null) {
            if (other.pathString != null) {
                return false;
            }
            return true;
        } else if (!this.pathString.equals(other.pathString)) {
            return false;
        } else {
            return true;
        }
    }
}
