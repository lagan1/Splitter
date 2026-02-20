
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public class IssueReporter {

    private final MontoyaApi api;

    public IssueReporter(MontoyaApi api) {
        this.api = api;
    }

    public void report(HttpRequestResponse requestResponse, ResponseAnalyzer.VulnerabilityType type) {
        if (type == ResponseAnalyzer.VulnerabilityType.NONE) {
            return;
        }

        AuditIssueSeverity severity;
        if ("High".equalsIgnoreCase(type.severity)) {
            severity = AuditIssueSeverity.HIGH;
        } else if ("Medium".equalsIgnoreCase(type.severity)) {
            severity = AuditIssueSeverity.MEDIUM;
        } else {
            severity = AuditIssueSeverity.INFORMATION;
        }

        AuditIssue issue = AuditIssue.auditIssue(
                type.name,
                "Found " + type.name + " via Splitter extension.",
                "The application appears to be vulnerable to CRLF injection or related attacks.",
                requestResponse.request().url(),
                severity,
                AuditIssueConfidence.CERTAIN,
                "Request analysis confirmed the vulnerability.",
                "Sanitize input to remove CRLF characters (%0d, %0a) and validate headers.",
                severity,
                requestResponse);

        api.siteMap().add(issue);
    }
}
