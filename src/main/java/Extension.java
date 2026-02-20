
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {

    // Keep reference to scanner to shutdown executors
    private SplitterScanner scanner;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Splitter - CRLF Injection & Response Splitting Scanner");

        // Initialize Components
        PayloadManager payloadManager = new PayloadManager();
        ResponseAnalyzer responseAnalyzer = new ResponseAnalyzer();
        IssueReporter issueReporter = new IssueReporter(montoyaApi);
        UIController uiController = new UIController();

        scanner = new SplitterScanner(
                montoyaApi,
                payloadManager,
                responseAnalyzer,
                issueReporter,
                uiController);

        // Register Context Menu (Manual Scan)
        montoyaApi.userInterface().registerContextMenuItemsProvider(new SplitterContextMenu(scanner));

        // Register UI
        montoyaApi.userInterface().registerSuiteTab("Splitter", uiController.getUi());

        // Logging
        montoyaApi.logging().logToOutput("Splitter Extension Loaded Successfully.");
        montoyaApi.logging().logToOutput("Manual context menu scanning enabled.");

        // Register Unload Handler
        montoyaApi.extension().registerUnloadingHandler(this::unload);
    }

    private void unload() {
        if (scanner != null) {
            scanner.shutdown();
        }
    }
}