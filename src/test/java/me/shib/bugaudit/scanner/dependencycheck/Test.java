package me.shib.bugaudit.scanner.dependencycheck;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.shib.bugaudit.scanner.dependencycheck.models.Dependency;
import me.shib.bugaudit.scanner.dependencycheck.models.DependencyCheckResult;
import me.shib.bugaudit.scanner.dependencycheck.models.Reference;
import me.shib.bugaudit.scanner.dependencycheck.models.Vulnerability;

import java.io.File;
import java.io.IOException;
import java.util.*;

public final class Test {

    public static void main(String[] args) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        DependencyCheckResult result = DependencyCheckResult.getResult(new File("dependency-check-report.json"));
        Map<String, Set<String>> map = new HashMap<>();
        int count = 0;
        for (Dependency dependency : result.getVulnerableDependencies()) {
            if(!dependency.getFileName().contains("shaded")) {
                System.out.println(dependency.getFileName());
            }
            count += dependency.getVulnerabilities().size();
            for (Vulnerability vulnerability : dependency.getVulnerabilities()) {
                Set<String> deps = map.get(vulnerability.getName());
                if (deps == null) {
                    deps = new HashSet<>();
                }
                deps.add(dependency.getFileName());
                map.put(vulnerability.getName(), deps);
            }
        }

        System.out.println(count);

    }

}
