
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Arrays;

public class ResponseAnalyzer {

    private static final List<Integer> ALLOWED_STATUS_CODES = Arrays.asList(
            200, 201, 202, 204, 205, 206, 207,
            301, 302, 307, 308);

    public enum VulnerabilityType {
        OPEN_REDIRECT("CRLF Injection leading to Open Redirect", "Medium"),
        HEADER_INJECTION("CRLF Injection allowing Arbitrary Header Injection", "Medium"),
        REFLECTED_XSS("CRLF Injection leading to Reflected XSS", "Medium"),
        RESPONSE_SPLITTING("HTTP Response Splitting", "High"),
        NONE("None", "Information");

        final String name;
        final String severity;

        VulnerabilityType(String name, String severity) {
            this.name = name;
            this.severity = severity;
        }
    }

    public VulnerabilityType analyze(HttpResponse response, String token) {
        if (!ALLOWED_STATUS_CODES.contains((int) response.statusCode())) {
            return VulnerabilityType.NONE;
        }

        // Regex is "Response headers only" in requirements.
        // Montoya's response.toString() might include body.
        // Better to join headers excluding body?
        // But headers are parsed.
        // "Header Matches REGEX... Apply matching on: Response headers only"
        // Let's iterate headers or just reconstruct them?
        // Actually, raw headers block is what we want.
        // Montoya doesn't give raw headers block easily without body?
        // response.headers() gives a list.
        // Let's match against the string representation of headers.

        StringBuilder headersBuilder = new StringBuilder();
        // Start line? No, regex starts with Header Name.
        // But the regex has `(?m)^...` which means start of line.
        // So we can just join headers with \r\n.
        for (var header : response.headers()) {
            headersBuilder.append(header.toString()).append("\r\n");
        }
        String headersString = headersBuilder.toString();

        // 1. Header Regex Match
        // Regex:
        // (?m)^(?:Location\s*?:\s*(?:https?:\/\/|\/\/|\/\\\\|\/\\)(?:[a-zA-Z0-9\-_\.@]*)www\.evil\.com\/?(\/|[^.].*)?$|(?:Set-Cookie\s*?:\s*(?:\s*?|.*?;\s*)?splitter=1(?:\s*?)(?:$|;)|splitter-x))
        // Dynamic Token Replacement: splitter_{token}=crlf

        String regex = "(?m)^(?:Location\\s*?:\\s*(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.\\@]*)www\\.evil\\.com\\/?(\\/|[^.].*)?$|(?:Set-Cookie\\s*?:\\s*(?:\\s*?|.*?;\\s*)?splitter_"
                + Pattern.quote(token) + "=crlf(?:\\s*?)(?:$|;)|splitter-x))";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(headersString);

        if (matcher.find()) {
            String matchedString = matcher.group();

            // VULNERABILITY CLASSIFICATION
            if (matchedString.toLowerCase().contains("location:")
                    && matchedString.toLowerCase().contains("www.evil.com")) {
                return VulnerabilityType.OPEN_REDIRECT;
            }

            // Check for Response Splitting (multiple responses)
            // "If multiple HTTP response lines appear" -> This might be in the BODY or
            // implicitly handled?
            // Usually, response splitting means we injected HTTP/1.x 200 OK...
            // If the body starts with HTTP/1.x ...
            // Or if we see "HTTP/1.1 200 OK" inside the headers/body?
            // "If multiple HTTP response lines appear"
            // The payloads include: /%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK...
            // If we see "HTTP/1.1 200 OK" in the response body or headers (apart from the
            // first line), it's splitting.

            // Count occurrences of "HTTP/1.1 \d\d\d" ?
            // Or specific regex for splitting?
            // Requirement: "If multiple HTTP response lines appear -> Title: HTTP Response
            // Splitting"
            // Let's check if the body contains "HTTP/1.1 200 OK" or similar.
            if (response.bodyToString().contains("HTTP/1.1 200 OK")) {
                return VulnerabilityType.RESPONSE_SPLITTING;
            }

            // XSS Check
            if (response.bodyToString().toLowerCase().contains("<script>alert('xss')") ||
                    response.bodyToString().toLowerCase().contains("<svg onload=alert") ||
                    response.bodyToString().toLowerCase().contains("<script>alert(document.cookie)") ||
                    response.bodyToString().toLowerCase().contains("<script>alert(document.domain)")) {
                return VulnerabilityType.REFLECTED_XSS;
            }

            // Default fallback for header injection (Set-Cookie or custom header)
            if (matchedString.toLowerCase().contains("set-cookie") || matchedString.contains("splitter")) {
                return VulnerabilityType.HEADER_INJECTION;
            }

            // Fallback
            return VulnerabilityType.HEADER_INJECTION;
        }

        return VulnerabilityType.NONE;
    }
}
