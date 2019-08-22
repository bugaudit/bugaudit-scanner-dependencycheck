package me.shib.bugaudit.scanner.dependencycheck;

import me.shib.bugaudit.commons.BugAuditException;

import java.io.IOException;

public final class Test {

    public static void main(String[] args) throws IOException, BugAuditException, InterruptedException {
        DependencyCheckScanner scanner = new DependencyCheckScanner();
        scanner.scan();
    }

}
