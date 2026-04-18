package verbTamper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class VerbTamper implements BurpExtension {

    private MontoyaApi api;
    private static final String[] VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"};

    private VerbTamperPanel mainPanel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.mainPanel = new VerbTamperPanel();

        api.userInterface().registerContextMenuItemsProvider(new VerbContextMenuProvider());
        api.userInterface().registerSuiteTab("Verb Tamper", mainPanel);
        api.logging().logToOutput("Verb Tamper loaded.");
    }

    private class VerbContextMenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> items = new ArrayList<>();

            Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
            List<HttpRequestResponse> messages = event.selectedRequestResponses();

            HttpRequest baseRequest = null;
            if (editor.isPresent()) {
                baseRequest = editor.get().requestResponse().request();
            } else if (!messages.isEmpty()) {
                baseRequest = messages.get(0).request();
            }

            if (baseRequest == null) return items;

            final HttpRequest req = baseRequest;
            JMenuItem item = new JMenuItem("Send to Verb Tamper");
            item.addActionListener(e -> SwingUtilities.invokeLater(() -> mainPanel.loadRequest(req)));
            items.add(item);
            return items;
        }
    }

    private class VerbTamperPanel extends JPanel {

        private final JTextArea requestArea;
        private final JTextArea responseArea;
        private final JComboBox<String> verbCombo;
        private final JButton sendBtn;
        private final JButton repeaterBtn;
        private final JLabel statusLabel;

        // Holds the service (host/port/https) from the original request
        private HttpService currentService = null;
        private boolean loading = false;

        VerbTamperPanel() {
            super(new BorderLayout(8, 8));
            setBorder(new EmptyBorder(12, 12, 12, 12));

            requestArea = new JTextArea();
            requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            requestArea.setLineWrap(false);
            requestArea.setText("Right-click any request in Burp and choose \"Send to Verb Tamper\"");
            requestArea.setForeground(Color.GRAY);
            JScrollPane reqScroll = new JScrollPane(requestArea);
            reqScroll.setBorder(BorderFactory.createTitledBorder("Request (editable)"));

            responseArea = new JTextArea();
            responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            responseArea.setEditable(false);
            responseArea.setBackground(new Color(28, 28, 28));
            responseArea.setForeground(new Color(180, 255, 180));
            JScrollPane respScroll = new JScrollPane(responseArea);
            respScroll.setBorder(BorderFactory.createTitledBorder("Response"));

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqScroll, respScroll);
            split.setResizeWeight(0.45);
            split.setDividerSize(6);

            verbCombo = new JComboBox<>(VERBS);
            verbCombo.setFont(verbCombo.getFont().deriveFont(Font.BOLD));
            verbCombo.setPreferredSize(new Dimension(100, 28));

            sendBtn = new JButton("Send");
            sendBtn.setBackground(new Color(60, 130, 60));
            sendBtn.setForeground(Color.WHITE);
            sendBtn.setOpaque(true);
            sendBtn.setEnabled(false);

            repeaterBtn = new JButton("Send to Repeater");
            repeaterBtn.setEnabled(false);

            statusLabel = new JLabel(" ");
            statusLabel.setForeground(Color.GRAY);

            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            toolbar.add(new JLabel("Verb:"));
            toolbar.add(verbCombo);
            toolbar.add(sendBtn);
            toolbar.add(repeaterBtn);
            toolbar.add(statusLabel);

            add(toolbar, BorderLayout.NORTH);
            add(split, BorderLayout.CENTER);

            sendBtn.addActionListener(e -> doSend());

            // Live update: when verb changes, rewrite the first line in the text area
            verbCombo.addActionListener(e -> {
                if (loading) return;
                String text = requestArea.getText();
                if (text.isEmpty() || text.startsWith("Right-click")) return;
                String newVerb = (String) verbCombo.getSelectedItem();
                String updated = swapMethod(text, newVerb);
                int caret = requestArea.getCaretPosition();
                requestArea.setText(updated);
                requestArea.setCaretPosition(Math.min(caret, updated.length()));
            });
        }

        void loadRequest(HttpRequest req) {
            currentService = req.httpService();

            loading = true;
            String method = req.method().toUpperCase();
            for (int i = 0; i < VERBS.length; i++) {
                if (VERBS[i].equals(method)) { verbCombo.setSelectedIndex(i); break; }
            }
            loading = false;

            requestArea.setForeground(UIManager.getColor("TextArea.foreground"));
            requestArea.setText(req.toString());
            requestArea.setCaretPosition(0);

            responseArea.setText("");
            statusLabel.setText("Loaded from " + (currentService != null ? currentService.host() : "unknown"));
            sendBtn.setEnabled(true);
            repeaterBtn.setEnabled(false);
        }

        private void doSend() {
            if (currentService == null) return;

            // Always re-parse from the text area so edits to path/headers are respected
            String rawText = requestArea.getText();
            String selectedVerb = (String) verbCombo.getSelectedItem();

            // Swap the method in the raw text so the request line is consistent,
            // then let the API parse it cleanly
            String updatedRaw = swapMethod(rawText, selectedVerb);

            HttpRequest request;
            try {
                request = HttpRequest.httpRequest(currentService, updatedRaw);
            } catch (Exception ex) {
                statusLabel.setText("Failed to parse request: " + ex.getMessage());
                return;
            }

            final HttpRequest finalRequest = request;

            sendBtn.setEnabled(false);
            sendBtn.setText("Sending...");
            statusLabel.setText("Sending " + selectedVerb + "...");
            responseArea.setText("");

            new Thread(() -> {
                try {
                    HttpRequestResponse result = api.http().sendRequest(finalRequest);

                    String responseText = result.response() != null
                            ? result.response().toString()
                            : "(no response received)";

                    String statusLine = responseText.split("\r?\n")[0];

                    SwingUtilities.invokeLater(() -> {
                        responseArea.setText(responseText);
                        responseArea.setCaretPosition(0);
                        statusLabel.setText(selectedVerb + " -> " + statusLine);
                        repeaterBtn.setEnabled(true);

                        for (var l : repeaterBtn.getActionListeners()) repeaterBtn.removeActionListener(l);
                        repeaterBtn.addActionListener(ev ->
                                api.repeater().sendToRepeater(finalRequest, "Verb Tamper - " + selectedVerb));
                    });
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        responseArea.setText("Error: " + ex.getMessage());
                        statusLabel.setText("Error: " + ex.getMessage());
                    });
                } finally {
                    SwingUtilities.invokeLater(() -> { sendBtn.setEnabled(true); sendBtn.setText("Send"); });
                }
            }).start();
        }

        /**
         * Replaces the HTTP method in the first line of a raw request string.
         * e.g. "POST /api/foo HTTP/2" -> "DELETE /api/foo HTTP/2"
         */
        private String swapMethod(String raw, String newMethod) {
            int firstSpace = raw.indexOf(' ');
            if (firstSpace == -1) return raw;
            return newMethod + raw.substring(firstSpace);
        }
    }
}
