
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class UIController {

    private final JPanel component;
    private final JCheckBox enableCheckBox;
    private final JCheckBox aggressiveModeCheckBox;
    private final DefaultTableModel logModel;
    private final JTable logTable;

    public UIController() {
        component = new JPanel(new BorderLayout());

        // Top Panel: Controls
        JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enableCheckBox = new JCheckBox("Enable Splitter");
        aggressiveModeCheckBox = new JCheckBox("Aggressive Mode (Threaded)");
        JButton clearButton = new JButton("Clear Logs");

        controlsPanel.add(enableCheckBox);
        controlsPanel.add(aggressiveModeCheckBox);
        controlsPanel.add(clearButton);

        component.add(controlsPanel, BorderLayout.NORTH);

        // Center Panel: Logs
        String[] columnNames = { "URL", "Payload", "Detection Type", "Status Code" };
        logModel = new DefaultTableModel(columnNames, 0);
        logTable = new JTable(logModel);
        JScrollPane scrollPane = new JScrollPane(logTable);

        component.add(scrollPane, BorderLayout.CENTER);

        // Action Listeners
        clearButton.addActionListener(e -> clearLogs());
    }

    public Component getUi() {
        return component;
    }

    public boolean isEnabled() {
        return enableCheckBox.isSelected();
    }

    public boolean isAggressiveMode() {
        return aggressiveModeCheckBox.isSelected();
    }

    public void log(String url, String payload, String type, int statusCode) {
        SwingUtilities.invokeLater(() -> logModel.addRow(new Object[] { url, payload, type, statusCode }));
    }

    public void clearLogs() {
        SwingUtilities.invokeLater(() -> logModel.setRowCount(0));
    }
}
