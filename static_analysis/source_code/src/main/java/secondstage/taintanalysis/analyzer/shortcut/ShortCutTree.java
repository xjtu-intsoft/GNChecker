package secondstage.taintanalysis.analyzer.shortcut;

import org.apache.commons.cli.HelpFormatter;
import secondstage.taintanalysis.taint.StmLocation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;


public class ShortCutTree {
    ArrayList<Path> paths = new ArrayList<>();

    public void print() {
        Iterator<Path> it = this.paths.iterator();
        while (it.hasNext()) {
            Path p = it.next();
            System.out.println(p.pathString);
        }
    }

    public boolean hasPath(Path path1) {
        Iterator<Path> it = this.paths.iterator();
        while (it.hasNext()) {
            Path path = it.next();
            if (path.pathString.startsWith(path1.pathString)) {
                return true;
            }
        }
        return false;
    }

    public Boolean tryPath(Path path1, Integer index) {
        String pathAdd = path1.pathString + HelpFormatter.DEFAULT_OPT_PREFIX + index;
        String pathCut = path1.pathString + "x" + index;
        Iterator<Path> it = this.paths.iterator();
        while (it.hasNext()) {
            Path path = it.next();
            if (path.pathString.startsWith(pathAdd)) {
                return true;
            }
            if (path.pathString.equals(pathCut)) {
                return false;
            }
        }
        return null;
    }

    public HashSet<StmLocation> getPathCleanStm(Path path1) {
        Iterator<Path> it = this.paths.iterator();
        while (it.hasNext()) {
            Path path = it.next();
            if (path.pathString.equals(path1.pathString)) {
                return path.getCleanAliasList();
            }
            if (path.pathString.startsWith(path1.pathString)) {
                return new HashSet<>();
            }
        }
        return null;
    }

    public boolean addPath(Path path1, HashSet<StmLocation> cleanAliasList) {
        if (!this.paths.contains(path1)) {
            for (int index = 0; index < this.paths.size(); index++) {
                Path path = this.paths.get(index);
                if (path1.pathString.startsWith(path.pathString)) {
                    if (cleanAliasList == null || cleanAliasList.isEmpty()) {
                        path.cleanAliasList = new HashSet<>();
                        path.pathString = new String(path1.pathString);
                        return true;
                    } else {
                        path.cleanAliasList = new HashSet<>(cleanAliasList);
                        path.pathString = new String(path1.pathString);
                        return true;
                    }
                }
            }
            this.paths.add(new Path(path1, cleanAliasList));
            return true;
        }
        return false;
    }
}
