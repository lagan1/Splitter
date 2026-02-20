
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SplitterScanner {

    private final MontoyaApi api;
    private final PayloadManager payloadManager;
    private final ResponseAnalyzer responseAnalyzer;
    private final IssueReporter issueReporter;
    private final UIController uiController;
    private final Set<String> testedUrls;
    private final ExecutorService executor;

    // Static resource extensions to skip
    private static final Set<String> EXTENSIONS_TO_SKIP = Set.of(
            ".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".svg", ".ico", ".woff", ".woff2");

    private final ExecutorService singleThreadExecutor;

    public SplitterScanner(MontoyaApi api, PayloadManager payloadManager, ResponseAnalyzer responseAnalyzer,
            IssueReporter issueReporter, UIController uiController) {
        this.api = api;
        this.payloadManager = payloadManager;
        this.responseAnalyzer = responseAnalyzer;
        this.issueReporter = issueReporter;
        this.uiController = uiController;
        this.testedUrls = ConcurrentHashMap.newKeySet();
        // Fixed thread pool for Aggressive Mode
        this.executor = Executors.newFixedThreadPool(10);
        this.singleThreadExecutor = Executors.newSingleThreadExecutor();
    }

    public void startScan(ContextMenuEvent event, PayloadManager.PayloadCategory category) {
        List<HttpRequestResponse> requestsToScan = new ArrayList<>();

        if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
            requestsToScan.addAll(event.selectedRequestResponses());
        } else if (event.messageEditorRequestResponse().isPresent()) {
            requestsToScan.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (requestsToScan.isEmpty()) {
            return;
        }

        ExecutorService modeExecutor = uiController.isAggressiveMode() ? executor : singleThreadExecutor;

        for (HttpRequestResponse reqResp : requestsToScan) {
            Runnable scanTask = () -> scan(reqResp, category);
            modeExecutor.submit(scanTask);
        }
    }

    private void scan(HttpRequestResponse baseReqResp, PayloadManager.PayloadCategory category) {
        HttpRequest baseRequest = baseReqResp.request();

        // Check for static resources
        String path = baseRequest.path().toLowerCase();
        for (String ext : EXTENSIONS_TO_SKIP) {
            if (path.endsWith(ext)) {
                return;
            }
        }

        // Deduplication (Scope: Method + Host + Path + Category?)
        // Requirement: "Deduplicate identical manual scans"
        // If user explicitly requests scan, should we skip?
        // "Scope of Execution... Only scan the selected request(s)"
        // "Deduplicate identical manual scans" implies if I select 10 requests and 5
        // are same URL, scan once?
        // OR if I scan the same URL twice in a row, skip second?
        // I will use Method+Host+Path+Category as key.

        String urlKey = baseRequest.method() + " " + baseRequest.httpService().host() + baseRequest.path() + "_"
                + category.name();
        if (testedUrls.contains(urlKey)) {
            // Log that we skipped?
            uiController.log(baseRequest.url(), "SKIPPED (Duplicate)", category.name(), 0);
            return;
        }
        testedUrls.add(urlKey);

        String token = payloadManager.generateToken();
        String hostname = baseRequest.httpService().host();
        String baseUrl = baseRequest.httpService().toString();

        List<String> payloads = payloadManager.getPayloads(baseUrl, hostname, token, category);

        if (payloads.isEmpty()) {
            uiController.log(baseRequest.url(), "NO PAYLOADS", category.name(), 0);
            return;
        }

        for (String payload : payloads) {
            try {
                // Inject payload into path
                HttpRequest modifiedRequest = baseRequest.withPath(payload);

                // Send request
                var response = api.http().sendRequest(modifiedRequest);

                // Analyze
                ResponseAnalyzer.VulnerabilityType vulnerability = responseAnalyzer.analyze(response.response(), token);

                // Report
                if (vulnerability != ResponseAnalyzer.VulnerabilityType.NONE) {
                    uiController.log(modifiedRequest.url(), payload, vulnerability.name,
                            response.response().statusCode());
                    issueReporter.report(response, vulnerability);
                } else {
                    uiController.log(modifiedRequest.url(), payload, "Clean", response.response().statusCode());
                }
            } catch (Exception e) {
                api.logging().logToError("Splitter Scan Error: " + e.getMessage());
            }
        }
    }

    public void shutdown() {
        executor.shutdown();
        singleThreadExecutor.shutdown();
    }
}
