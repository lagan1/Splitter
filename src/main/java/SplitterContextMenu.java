
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.awt.Component;

public class SplitterContextMenu implements ContextMenuItemsProvider {

    private final SplitterScanner scanner;

    public SplitterContextMenu(SplitterScanner scanner) {
        this.scanner = scanner;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        // Validation: Only show for HttpRequestResponse (Proxy/Repeater/Target)
        // If no request is selected, return empty list
        if (event.selectedRequestResponses() == null || event.selectedRequestResponses().isEmpty()) {
            // Try message editor?
            if (event.messageEditorRequestResponse().isEmpty()) {
                return new ArrayList<>();
            }
        }

        List<Component> menuList = new ArrayList<>();

        JMenu splitterMenu = new JMenu("Splitter");

        JMenuItem testAll = new JMenuItem("Test for All");
        testAll.addActionListener(e -> scanner.startScan(event, PayloadManager.PayloadCategory.ALL));

        JMenuItem testHeader = new JMenuItem("Test for Arbitrary Header Injection");
        testHeader.addActionListener(e -> scanner.startScan(event, PayloadManager.PayloadCategory.HEADER_INJECTION));

        JMenuItem testXss = new JMenuItem("Test for XSS");
        testXss.addActionListener(e -> scanner.startScan(event, PayloadManager.PayloadCategory.XSS));

        JMenuItem testRedirect = new JMenuItem("Test for Open Redirect");
        testRedirect.addActionListener(e -> scanner.startScan(event, PayloadManager.PayloadCategory.OPEN_REDIRECT));

        JMenuItem testSplitting = new JMenuItem("Test for HTTP Response Splitting");
        testSplitting
                .addActionListener(e -> scanner.startScan(event, PayloadManager.PayloadCategory.RESPONSE_SPLITTING));

        splitterMenu.add(testAll);
        splitterMenu.add(testHeader);
        splitterMenu.add(testXss);
        splitterMenu.add(testRedirect);
        splitterMenu.add(testSplitting);

        menuList.add(splitterMenu);

        return menuList;
    }
}
