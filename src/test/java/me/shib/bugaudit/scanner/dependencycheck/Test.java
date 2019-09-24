package me.shib.bugaudit.scanner.dependencycheck;

import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.dependencycheck.models.Dependency;
import me.shib.bugaudit.scanner.dependencycheck.models.DependencyCheckResult;
import me.shib.bugaudit.scanner.dependencycheck.models.Vulnerability;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Test {

    public static void main(String[] args) throws IOException, BugAuditException, InterruptedException {
        DependencyCheckResult result = DependencyCheckResult.getResult(new File("depout.json"));
        List<Dependency> dependencies = result.getVulnerableDependencies();
        Map<String, List<Dependency>> uniqueDependencies = new HashMap<>();
        for (Dependency dependency : dependencies) {
            if (!dependency.getFileName().contains("(shaded:") &&
                    dependency.getFileName().toLowerCase().endsWith(".jar")) {
                List<Dependency> deps = uniqueDependencies.get(dependency.getName());
                if (deps == null) {
                    deps = new ArrayList<>();
                }
                deps.add(dependency);
                uniqueDependencies.put(dependency.getName(), deps);
            }
        }
        for (String dependency : uniqueDependencies.keySet()) {
            List<Dependency> deps = uniqueDependencies.get(dependency);
            if (deps.size() > 1) {
                System.out.println("Dependency: " + dependency);
                for (Dependency dep : deps) {
                    List<Vulnerability> vulnerabilities = dep.getVulnerabilities();
                    System.out.println(dep.getFileName() + ":");
                    if (vulnerabilities != null) {
                        for (Vulnerability vulnerability : dep.getVulnerabilities()) {
                            System.out.println(vulnerability.getName());
                        }
                    }
                }
                System.out.println();
            }
            //System.out.println(dependency);
        }
        System.out.println(uniqueDependencies.size());
    }

}
