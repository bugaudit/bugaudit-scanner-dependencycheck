package me.shib.bugaudit.scanner.dependencycheck;

import me.shib.bugaudit.commons.BugAuditException;
import me.shib.bugaudit.scanner.BugAuditScanner;
import me.shib.bugaudit.scanner.BugAuditScannerConfig;
import me.shib.bugaudit.scanner.Lang;

import java.io.IOException;

public class DependencyCheckScanner extends BugAuditScanner {

    private static final transient Lang lang = Lang.Undefined;
    private static final transient String tool = "DependencyCheck";
    private static final transient String resultFilePath = "bugaudit-dependency-check-result.json";

    public DependencyCheckScanner() throws BugAuditException {
        super();
        this.getBugAuditScanResult().addKey("Vulnerable-Dependency");
    }

    @Override
    protected BugAuditScannerConfig getDefaultScannerConfig() {
        return null;
    }

    @Override
    protected Lang getLang() {
        return lang;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public void scan() throws IOException, InterruptedException {
        runCommand("");

    }
}
