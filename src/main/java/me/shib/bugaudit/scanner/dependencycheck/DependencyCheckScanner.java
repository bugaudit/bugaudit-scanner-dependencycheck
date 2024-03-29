package me.shib.bugaudit.scanner.dependencycheck;

import me.shib.bugaudit.commons.BugAuditContent;
import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.Bug;
import me.shib.bugaudit.scanner.BugAuditScanResult;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.Lang;
import me.shib.bugaudit.scanner.dependencycheck.models.Dependency;
import me.shib.bugaudit.scanner.dependencycheck.models.DependencyCheckResult;
import me.shib.bugaudit.scanner.dependencycheck.models.Reference;
import me.shib.bugaudit.scanner.dependencycheck.models.Vulnerability;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DependencyCheckScanner extends BugAuditScanner {

    private static final transient String cweBaseURL = "https://cwe.mitre.org/data/definitions/";
    private static final transient String tool = "DependencyCheck";
    private static final transient File dependencyCheckReportFile = new File("bugaudit-dependency-check-result.json");
    private static final transient int cveRecheckHours = 24;

    private BugAuditScanResult bugauditResult;

    public DependencyCheckScanner() throws BugAuditException {
        super();
        this.bugauditResult = this.getBugAuditScanResult();
        this.bugauditResult.addKey("Vulnerable-Dependency");
    }

    @Override
    protected boolean isLangSupported(Lang lang) {
        return lang == Lang.Java;
    }

    @Override
    public String getTool() {
        return tool;
    }

    private int getPriorityForSeverity(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return 1;
            case "HIGH":
                return 2;
            case "MEDIUM":
                return 3;
            case "LOW":
                return 4;
            default:
                return 3;
        }
    }

    private String getUrlForCWE(String cwe) {
        if (cwe.toUpperCase().startsWith("CWE-")) {
            return cweBaseURL + cwe.toUpperCase().replace("CWE-", "") + ".html";
        }
        return null;
    }

    private String getDescription(Dependency dependency, Vulnerability vulnerability) throws BugAuditException {
        StringBuilder description = new StringBuilder();
        description.append("A known vulnerability was found in **")
                .append(dependency.getFileName()).append("** of ").append("**[")
                .append(bugauditResult.getRepo()).append("](")
                .append(getBugAuditScanResult().getRepo().getWebUrl()).append(")**.\n");
        description.append("**[").append(vulnerability.getName()).append("](").append(getUrlForCVE(vulnerability.getName()))
                .append("):**").append("\n");
        description.append(" * **Component:** ").append(dependency.getFileName()).append("\n");
        String currentPath = System.getProperty("user.dir") + "/";
        if (dependency.getFilePath().startsWith(currentPath)) {
            description.append(" * **Path:** ").append(dependency.getFilePath().replaceFirst(currentPath, "")).append("\n");
        }
        description.append(" * **Description:** ").append(vulnerability.getDescription()).append("\n");
        if (vulnerability.getCvssv2() != null) {
            description.append(" * **CVSS v2 Score:** ").append(vulnerability.getCvssv2().getScore()).append("\n");
        }
        if (vulnerability.getCvssv3() != null) {
            description.append(" * **CVSS v3 Score:** ").append(vulnerability.getCvssv3().getBaseScore()).append("\n");
        }
        description.append(" * **Severity:** ").append(vulnerability.getSeverity()).append("\n");

        description.append(" * **Applicable CWEs:**");
        for (String cwe : vulnerability.getCwes()) {
            String cweURL = getUrlForCWE(cwe);
            if (cweURL != null) {
                description.append(" **[").append(cwe).append("](").append(cweURL).append(")**");
            } else {
                description.append(" **").append(cwe).append("**");
            }
        }
        description.append("\n");

        if (vulnerability.getNotes() != null && !vulnerability.getNotes().isEmpty()) {
            description.append(" * **Notes:** ").append(vulnerability.getNotes()).append("\n");
        }

        if (vulnerability.getReferences() != null && vulnerability.getReferences().size() > 0) {
            description.append("\n**References:**\n");
            for (Reference reference : vulnerability.getReferences()) {
                if (reference.getName() != null && !reference.getName().isEmpty()) {
                    if (reference.getUrl() != null && !reference.getUrl().isEmpty()) {
                        description.append(" * [").append(reference.getName()).append("](")
                                .append(reference.getUrl()).append(")\n");
                    } else {
                        description.append(" * ").append(reference.getName()).append("\n");
                    }
                } else if (reference.getUrl() != null && !reference.getUrl().isEmpty()) {
                    description.append(" * [").append(reference.getUrl()).append("](")
                            .append(reference.getUrl()).append(")\n");
                }
            }
        }
        return description.toString();
    }

    private void processDependencyCheckReport(DependencyCheckResult dependencyCheckResult) throws BugAuditException {
        if (bugauditResult.getBugs().size() == 0) {
            class VulnDependencyPair {
                private Vulnerability vulnerability;
                private Dependency dependency;

                private VulnDependencyPair(Vulnerability vulnerability, Dependency dependency) {
                    this.vulnerability = vulnerability;
                    this.dependency = dependency;
                }
            }
            Map<String, List<VulnDependencyPair>> vulnDepsMap = new HashMap<>();
            List<Dependency> vulnerableDependencies = dependencyCheckResult.getVulnerableDependencies();
            for (Dependency dependency : vulnerableDependencies) {
                if (!dependency.getFileName().contains("(shaded: ") &&
                        dependency.getFileName().toLowerCase().endsWith(".jar")) {
                    List<Vulnerability> vulnerabilities = dependency.getVulnerabilities();
                    if (vulnerabilities != null) {
                        for (Vulnerability vulnerability : vulnerabilities) {
                            if (vulnerability.getName() != null &&
                                    vulnerability.getName().toUpperCase().startsWith("CVE-")) {
                                String key = dependency.getName().toLowerCase() + "-" + vulnerability.getName();
                                List<VulnDependencyPair> vulnDependencyPairs = vulnDepsMap.get(key);
                                if (vulnDependencyPairs == null) {
                                    vulnDependencyPairs = new ArrayList<>();
                                }
                                vulnDependencyPairs.add(new VulnDependencyPair(vulnerability, dependency));
                                vulnDepsMap.put(key, vulnDependencyPairs);
                            }
                        }
                    }
                }
            }

            for (String key : vulnDepsMap.keySet()) {
                List<VulnDependencyPair> vulnDependencyPairs = vulnDepsMap.get(key);
                if (vulnDependencyPairs != null && vulnDependencyPairs.size() > 0) {
                    Vulnerability vulnerability = vulnDependencyPairs.get(0).vulnerability;
                    Dependency dependency = vulnDependencyPairs.get(0).dependency;
                    String cve = vulnerability.getName();
                    String title = "Vulnerability (" + cve + ") found in " + dependency.getName() +
                            " of " + bugauditResult.getRepo();
                    int priority = 10;
                    for (VulnDependencyPair vulnDependencyPair : vulnDependencyPairs) {
                        int vulnPriority = getPriorityForSeverity(vulnDependencyPair.vulnerability.getSeverity());
                        if (vulnPriority < priority) {
                            priority = vulnPriority;
                        }
                    }
                    Bug bug = new Bug(title, priority);
                    bug.setDescription(new BugAuditContent(getDescription(dependency, vulnerability)));
                    if (vulnerability.getCwes() != null) {
                        for (String cwe : vulnerability.getCwes()) {
                            bug.addType(cwe);
                        }
                    }
                    bug.addKey(dependency.getName());
                    bug.addKey(cve);
                    bug.addTag(dependency.getFileName());
                    bugauditResult.addBug(bug);
                }
            }
        }
    }

    private void runDependecyCheck() throws IOException, InterruptedException {
        runCommand("dependency-check" +
                " --cveValidForHours " + cveRecheckHours +
                " --format JSON" +
                " --out " + dependencyCheckReportFile.getAbsolutePath() +
                " --scan .");
    }

    @Override
    public void scan() throws IOException, InterruptedException, BugAuditException {
        if (!isParserOnly()) {
            dependencyCheckReportFile.delete();
            runDependecyCheck();
        }
        DependencyCheckResult dependencyCheckResult = DependencyCheckResult.getResult(dependencyCheckReportFile);
        processDependencyCheckReport(dependencyCheckResult);
    }
}
