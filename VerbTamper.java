package verbTamper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

public class VerbTamper implements BurpExtension {

    private MontoyaApi api;
    private static final String[] VERBS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"};
    private VerbTamperPanel mainPanel;
    private Registration tabRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.mainPanel = new VerbTamperPanel();
        api.userInterface().registerContextMenuItemsProvider(new VerbContextMenuProvider());
        tabRegistration = api.userInterface().registerSuiteTab("Verb Tamper", mainPanel);
        api.logging().logToOutput("Verb Tamper loaded.");
    }

    // ── History entry ─────────────────────────────────────────────────────────

    private static class HistoryEntry {
        final String requestText;
        final String verb;
        final String responseText;
        final HttpService service;

        HistoryEntry(String requestText, String verb, String responseText, HttpService service) {
            this.requestText = requestText;
            this.verb = verb;
            this.responseText = responseText;
            this.service = service;
        }
    }

    // ── Context Menu ──────────────────────────────────────────────────────────

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
            item.addActionListener(e -> {
                highlightProxyItem(req);
                SwingUtilities.invokeLater(() -> mainPanel.loadRequest(req));
            });
            items.add(item);
            return items;
        }
    }

    private void highlightProxyItem(HttpRequest req) {
        new Thread(() -> {
            try {
                var history = api.proxy().history();
                for (int i = history.size() - 1; i >= 0; i--) {
                    var item = history.get(i);
                    if (item.request().toString().equals(req.toString())) {
                        item.annotations().setHighlightColor(HighlightColor.ORANGE);
                        Thread.sleep(400);
                        item.annotations().setHighlightColor(HighlightColor.NONE);
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }).start();
    }

    // ── Main Panel ────────────────────────────────────────────────────────────

    private class VerbTamperPanel extends JPanel {

        private final JTextArea requestArea;
        private final JTextArea responseArea;
        private final JComboBox<String> verbCombo;
        private final JButton sendBtn;
        private final JButton scanBtn;
        private final JButton repeaterBtn;
        private final JButton backBtn;
        private final JButton forwardBtn;
        private final JButton clearBtn;
        private final JButton copyReqBtn;
        private final JButton copyRespBtn;
        private final JButton diffBtn;
        private final JLabel statusLabel;
        private final JLabel historyLabel;

        // Auth token manager
        private final DefaultListModel<String> tokenListModel = new DefaultListModel<>();
        private final JList<String> tokenList = new JList<>(tokenListModel);

        private HttpService currentService = null;
        private boolean loading = false;

        private final List<HistoryEntry> history = new ArrayList<>();
        private int historyIndex = -1;
        private boolean navigating = false;

        // For diff — keeps last two responses
        private String lastResponse = null;
        private String currentResponse = null;

        VerbTamperPanel() {
            super(new BorderLayout(8, 8));
            setBorder(new EmptyBorder(8, 8, 8, 8));

            // ── Request area ──
            requestArea = new JTextArea();
            requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            requestArea.setLineWrap(false);
            requestArea.setText("Right-click any request in Burp and choose \"Send to Verb Tamper\"");
            requestArea.setForeground(Color.GRAY);
            JScrollPane reqScroll = new JScrollPane(requestArea);
            reqScroll.setBorder(BorderFactory.createTitledBorder("Request (editable)"));

            // ── Response area ──
            responseArea = new JTextArea();
            responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            responseArea.setEditable(false);
            responseArea.setBackground(new Color(28, 28, 28));
            responseArea.setForeground(new Color(180, 255, 180));
            JScrollPane respScroll = new JScrollPane(responseArea);
            respScroll.setBorder(BorderFactory.createTitledBorder("Response"));

            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqScroll, respScroll);
            mainSplit.setResizeWeight(0.45);
            mainSplit.setDividerSize(6);

            // ── Toolbar row 1: nav + verb + send ──
            backBtn = new JButton("◀");
            backBtn.setToolTipText("Previous request");
            backBtn.setEnabled(false);
            backBtn.setMargin(new Insets(2, 6, 2, 6));

            forwardBtn = new JButton("▶");
            forwardBtn.setToolTipText("Next request");
            forwardBtn.setEnabled(false);
            forwardBtn.setMargin(new Insets(2, 6, 2, 6));

            historyLabel = new JLabel("0 / 0");
            historyLabel.setForeground(Color.GRAY);
            historyLabel.setFont(historyLabel.getFont().deriveFont(11f));

            verbCombo = new JComboBox<>(VERBS);
            verbCombo.setFont(verbCombo.getFont().deriveFont(Font.BOLD));
            verbCombo.setPreferredSize(new Dimension(100, 28));

            sendBtn = new JButton("Send");
            sendBtn.setBackground(new Color(60, 130, 60));
            sendBtn.setForeground(Color.WHITE);
            sendBtn.setOpaque(true);
            sendBtn.setEnabled(false);

            scanBtn = new JButton("Scan All Verbs");
            scanBtn.setBackground(new Color(70, 100, 180));
            scanBtn.setForeground(Color.WHITE);
            scanBtn.setOpaque(true);
            scanBtn.setEnabled(false);

            repeaterBtn = new JButton("→ Repeater");
            repeaterBtn.setEnabled(false);

            clearBtn = new JButton("Clear");
            clearBtn.setForeground(new Color(180, 60, 60));

            diffBtn = new JButton("Diff");
            diffBtn.setToolTipText("Diff last two responses");
            diffBtn.setEnabled(false);

            copyReqBtn = new JButton("Copy Req");
            copyRespBtn = new JButton("Copy Resp");
            copyRespBtn.setEnabled(false);

            statusLabel = new JLabel(" ");
            statusLabel.setForeground(Color.GRAY);

            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
            toolbar.add(backBtn);
            toolbar.add(forwardBtn);
            toolbar.add(historyLabel);
            toolbar.add(makeSep());
            toolbar.add(new JLabel("Verb:"));
            toolbar.add(verbCombo);
            toolbar.add(sendBtn);
            toolbar.add(scanBtn);
            toolbar.add(repeaterBtn);
            toolbar.add(makeSep());
            toolbar.add(diffBtn);
            toolbar.add(copyReqBtn);
            toolbar.add(copyRespBtn);
            toolbar.add(clearBtn);
            toolbar.add(statusLabel);

            // ── Auth token panel ──
            JPanel authPanel = buildAuthPanel();

            // ── Right side: auth panel ──
            JSplitPane outerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mainSplit, authPanel);
            outerSplit.setResizeWeight(0.78);
            outerSplit.setDividerSize(6);

            add(toolbar, BorderLayout.NORTH);
            add(outerSplit, BorderLayout.CENTER);

            // ── Listeners ──

            verbCombo.addActionListener(e -> {
                if (loading || navigating) return;
                String text = requestArea.getText();
                if (text.isEmpty() || text.startsWith("Right-click")) return;
                String updated = swapMethod(text, (String) verbCombo.getSelectedItem());
                int caret = requestArea.getCaretPosition();
                requestArea.setText(updated);
                requestArea.setCaretPosition(Math.min(caret, updated.length()));
            });

            sendBtn.addActionListener(e -> doSend());
            scanBtn.addActionListener(e -> doScan());
            backBtn.addActionListener(e -> navigate(-1));
            forwardBtn.addActionListener(e -> navigate(1));

            clearBtn.addActionListener(e -> {
                requestArea.setText("");
                requestArea.setForeground(UIManager.getColor("TextArea.foreground"));
                responseArea.setText("");
                statusLabel.setText(" ");
                sendBtn.setEnabled(false);
                scanBtn.setEnabled(false);
                repeaterBtn.setEnabled(false);
                copyRespBtn.setEnabled(false);
                diffBtn.setEnabled(false);
                currentService = null;
                updateTitle(null);
            });

            copyReqBtn.addActionListener(e -> {
                String text = requestArea.getText();
                if (!text.isEmpty()) copyToClipboard(text);
            });

            copyRespBtn.addActionListener(e -> {
                String text = responseArea.getText();
                if (!text.isEmpty()) copyToClipboard(text);
            });

            diffBtn.addActionListener(e -> showDiff(lastResponse, currentResponse));
        }

        private JSeparator makeSep() {
            JSeparator sep = new JSeparator(SwingConstants.VERTICAL);
            sep.setPreferredSize(new Dimension(2, 22));
            return sep;
        }

        // ── Auth Panel ────────────────────────────────────────────────────────

        private JPanel buildAuthPanel() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(BorderFactory.createTitledBorder("Auth Tokens"));
            panel.setPreferredSize(new Dimension(220, 0));

            tokenList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            tokenList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            tokenList.setCellRenderer(new DefaultListCellRenderer() {
                @Override
                public Component getListCellRendererComponent(JList<?> list, Object value,
                        int index, boolean isSelected, boolean cellHasFocus) {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                    String s = value.toString();
                    // Show label if format is "label::token", else truncate
                    if (s.contains("::")) {
                        setText(s.split("::", 2)[0]);
                    } else {
                        setText(s.length() > 24 ? s.substring(0, 12) + "..." + s.substring(s.length() - 8) : s);
                    }
                    setToolTipText(s.contains("::") ? s.split("::", 2)[1] : s);
                    return this;
                }
            });

            JScrollPane scroll = new JScrollPane(tokenList);

            // Buttons
            JButton addBtn = new JButton("Add");
            JButton applyBtn = new JButton("Apply");
            applyBtn.setBackground(new Color(60, 130, 60));
            applyBtn.setForeground(Color.WHITE);
            applyBtn.setOpaque(true);
            JButton removeBtn = new JButton("Remove");

            JPanel btnRow = new JPanel(new GridLayout(1, 3, 3, 0));
            btnRow.add(addBtn);
            btnRow.add(applyBtn);
            btnRow.add(removeBtn);

            panel.add(scroll, BorderLayout.CENTER);
            panel.add(btnRow, BorderLayout.SOUTH);

            // Add token
            addBtn.addActionListener(e -> {
                JTextField labelField = new JTextField();
                JTextArea tokenField = new JTextArea(4, 30);
                tokenField.setLineWrap(true);
                tokenField.setWrapStyleWord(true);
                Object[] msg = {
                    "Label (e.g. admin, hacker):", labelField,
                    "Token (paste full JWT):", new JScrollPane(tokenField)
                };
                int r = JOptionPane.showConfirmDialog(panel, msg, "Add Auth Token",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (r == JOptionPane.OK_OPTION) {
                    String label = labelField.getText().trim();
                    String token = tokenField.getText().trim().replaceAll("\\s+", "");
                    if (!token.isEmpty()) {
                        String entry = label.isEmpty() ? token : label + "::" + token;
                        tokenListModel.addElement(entry);
                    }
                }
            });

            // Apply selected token to request
            applyBtn.addActionListener(e -> {
                String selected = tokenList.getSelectedValue();
                if (selected == null) {
                    statusLabel.setText("Select a token first");
                    return;
                }
                String token = selected.contains("::") ? selected.split("::", 2)[1] : selected;
                String raw = requestArea.getText();
                if (raw.isEmpty() || raw.startsWith("Right-click")) {
                    statusLabel.setText("Load a request first");
                    return;
                }
                // Replace existing Authorization header or add one
                String updated;
                if (raw.contains("Authorization:")) {
                    updated = raw.replaceAll("(?m)^Authorization:.*$", "Authorization: Bearer " + token);
                } else {
                    // Insert after Host line
                    updated = raw.replaceFirst("(?m)^(Host:.*)$", "$1\r\nAuthorization: Bearer " + token);
                }
                requestArea.setText(updated);
                String label = selected.contains("::") ? selected.split("::", 2)[0] : "token";
                statusLabel.setText("Applied: " + label);
            });

            removeBtn.addActionListener(e -> {
                int idx = tokenList.getSelectedIndex();
                if (idx >= 0) tokenListModel.remove(idx);
            });

            return panel;
        }

        // ── Load request ──────────────────────────────────────────────────────

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
            statusLabel.setText("Loaded — " + (currentService != null ? currentService.host() : "unknown"));
            sendBtn.setEnabled(true);
            scanBtn.setEnabled(true);
            repeaterBtn.setEnabled(false);
            copyRespBtn.setEnabled(false);
            updateTitle(req.path());
        }

        // ── Send ──────────────────────────────────────────────────────────────

        private void doSend() {
            if (currentService == null) return;

            String rawText = sanitiseHeaders(requestArea.getText());
            String selectedVerb = (String) verbCombo.getSelectedItem();
            String updatedRaw = swapMethod(rawText, selectedVerb);

            HttpRequest request;
            try { request = HttpRequest.httpRequest(currentService, updatedRaw); }
            catch (Exception ex) { statusLabel.setText("Parse error: " + ex.getMessage()); return; }

            final HttpRequest finalRequest = request;
            final String rawSnapshot = requestArea.getText();

            sendBtn.setEnabled(false);
            sendBtn.setText("Sending...");
            statusLabel.setText("Sending " + selectedVerb + "...");
            responseArea.setText("");

            new Thread(() -> {
                try {
                    boolean isHttp2 = updatedRaw.split("\r?\n")[0].toUpperCase().contains("HTTP/2");
                    HttpMode mode = isHttp2 ? HttpMode.HTTP_2 : HttpMode.AUTO;
                    HttpRequestResponse result = api.http().sendRequest(finalRequest, mode);

                    String responseText = result.response() != null ? result.response().toString() : "(no response)";
                    String statusLine = responseText.split("\r?\n")[0];

                    HistoryEntry entry = new HistoryEntry(rawSnapshot, selectedVerb, responseText, currentService);

                    SwingUtilities.invokeLater(() -> {
                        // Shift diff window
                        lastResponse = currentResponse;
                        currentResponse = responseText;
                        diffBtn.setEnabled(lastResponse != null);

                        if (historyIndex < history.size() - 1)
                            history.subList(historyIndex + 1, history.size()).clear();
                        history.add(entry);
                        historyIndex = history.size() - 1;

                        responseArea.setText(responseText);
                        responseArea.setCaretPosition(0);
                        statusLabel.setText(colourStatus(selectedVerb + " → " + statusLine));
                        copyRespBtn.setEnabled(true);

                        repeaterBtn.setEnabled(true);
                        for (var l : repeaterBtn.getActionListeners()) repeaterBtn.removeActionListener(l);
                        repeaterBtn.addActionListener(ev ->
                                api.repeater().sendToRepeater(finalRequest, "Verb Tamper - " + selectedVerb));

                        updateNavButtons();
                        updateTitle(finalRequest.path());
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

        // ── Scan all verbs ────────────────────────────────────────────────────

        private void doScan() {
            if (currentService == null) return;

            String rawText = sanitiseHeaders(requestArea.getText());
            boolean isHttp2 = rawText.split("\r?\n")[0].toUpperCase().contains("HTTP/2");
            HttpMode mode = isHttp2 ? HttpMode.HTTP_2 : HttpMode.AUTO;

            // Results table
            String[] cols = {"Verb", "Status", "Length", "Response Preview"};
            DefaultTableModel model = new DefaultTableModel(cols, 0) {
                public boolean isCellEditable(int r, int c) { return false; }
            };
            JTable table = new JTable(model);
            table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            table.setRowHeight(22);
            table.getColumnModel().getColumn(0).setPreferredWidth(70);
            table.getColumnModel().getColumn(1).setPreferredWidth(80);
            table.getColumnModel().getColumn(2).setPreferredWidth(70);
            table.getColumnModel().getColumn(3).setPreferredWidth(400);

            // Colour rows by status
            table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object value,
                        boolean sel, boolean focus, int row, int col) {
                    super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                    String status = (String) t.getModel().getValueAt(row, 1);
                    if (!sel) {
                        if (status.startsWith("2")) setBackground(new Color(220, 255, 220));
                        else if (status.startsWith("3")) setBackground(new Color(255, 245, 200));
                        else if (status.startsWith("4")) setBackground(new Color(255, 225, 225));
                        else if (status.startsWith("5")) setBackground(new Color(255, 200, 200));
                        else setBackground(Color.WHITE);
                        setForeground(Color.BLACK);
                    }
                    return this;
                }
            });

            JDialog dialog = new JDialog();
            dialog.setTitle("Scan All Verbs — " + (currentService != null ? currentService.host() : "") + rawText.split("\r?\n")[0].replaceAll("^\\w+\\s", "").replaceAll("\\s.*", ""));
            dialog.setSize(750, 380);
            dialog.setLocationRelativeTo(null);

            JLabel scanStatus = new JLabel("Scanning 0 / " + VERBS.length + "...");
            scanStatus.setBorder(new EmptyBorder(4, 8, 4, 8));

            dialog.setLayout(new BorderLayout(4, 4));
            dialog.add(scanStatus, BorderLayout.NORTH);
            dialog.add(new JScrollPane(table), BorderLayout.CENTER);
            dialog.setVisible(true);

            AtomicInteger done = new AtomicInteger(0);

            for (String verb : VERBS) {
                new Thread(() -> {
                    try {
                        String verbRaw = swapMethod(rawText, verb);
                        HttpRequest req = HttpRequest.httpRequest(currentService, verbRaw);
                        HttpRequestResponse result = api.http().sendRequest(req, mode);

                        String respText = result.response() != null ? result.response().toString() : "";
                        String[] respLines = respText.split("\r?\n");
                        String statusCode = respLines.length > 0 ? respLines[0].replaceAll("HTTP/\\S+\\s+", "").trim() : "?";
                        String statusNum = statusCode.length() >= 3 ? statusCode.substring(0, 3) : statusCode;
                        int length = respText.length();
                        String preview = respLines.length > 1 ? respLines[respLines.length - 1] : "";
                        if (preview.length() > 80) preview = preview.substring(0, 80) + "...";

                        final String fVerb = verb, fStatus = statusNum, fPreview = preview;
                        final int fLen = length;
                        SwingUtilities.invokeLater(() -> {
                            model.addRow(new Object[]{fVerb, fStatus, fLen + "b", fPreview});
                            int n = done.incrementAndGet();
                            scanStatus.setText(n < VERBS.length ? "Scanning " + n + " / " + VERBS.length + "..." : "Done — " + VERBS.length + " verbs tested");
                        });
                    } catch (Exception ex) {
                        String fVerb = verb;
                        SwingUtilities.invokeLater(() -> {
                            model.addRow(new Object[]{fVerb, "ERR", "-", ex.getMessage()});
                            done.incrementAndGet();
                        });
                    }
                }).start();
            }
        }

        // ── Diff ──────────────────────────────────────────────────────────────

        private void showDiff(String a, String b) {
            if (a == null || b == null) return;

            JDialog dialog = new JDialog();
            dialog.setTitle("Response Diff");
            dialog.setSize(1000, 600);
            dialog.setLocationRelativeTo(null);

            String[] aLines = a.split("\r?\n");
            String[] bLines = b.split("\r?\n");

            JTextPane diffPane = new JTextPane();
            diffPane.setEditable(false);
            diffPane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            diffPane.setContentType("text/html");

            StringBuilder html = new StringBuilder("<html><body style='font-family:monospace;font-size:12px;'>");
            int max = Math.max(aLines.length, bLines.length);
            for (int i = 0; i < max; i++) {
                String la = i < aLines.length ? escape(aLines[i]) : "<i style='color:grey'>(no line)</i>";
                String lb = i < bLines.length ? escape(bLines[i]) : "<i style='color:grey'>(no line)</i>";
                if (la.equals(lb)) {
                    html.append("<div style='padding:1px 4px;'>").append(la).append("</div>");
                } else {
                    html.append("<div style='background:#ffe0e0;padding:1px 4px;'>- ").append(la).append("</div>");
                    html.append("<div style='background:#e0ffe0;padding:1px 4px;'>+ ").append(lb).append("</div>");
                }
            }
            html.append("</body></html>");
            diffPane.setText(html.toString());

            JLabel legend = new JLabel("  Red = previous response   Green = current response");
            legend.setFont(legend.getFont().deriveFont(11f));
            legend.setBorder(new EmptyBorder(4, 8, 4, 8));

            dialog.setLayout(new BorderLayout());
            dialog.add(legend, BorderLayout.NORTH);
            dialog.add(new JScrollPane(diffPane), BorderLayout.CENTER);
            dialog.setVisible(true);
        }

        private String escape(String s) {
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }

        // ── Navigation ────────────────────────────────────────────────────────

        private void navigate(int direction) {
            int newIndex = historyIndex + direction;
            if (newIndex < 0 || newIndex >= history.size()) return;
            historyIndex = newIndex;
            HistoryEntry entry = history.get(historyIndex);

            navigating = true;
            for (int i = 0; i < VERBS.length; i++) {
                if (VERBS[i].equals(entry.verb)) { verbCombo.setSelectedIndex(i); break; }
            }
            requestArea.setForeground(UIManager.getColor("TextArea.foreground"));
            requestArea.setText(entry.requestText);
            requestArea.setCaretPosition(0);
            responseArea.setText(entry.responseText);
            responseArea.setCaretPosition(0);
            currentService = entry.service;
            sendBtn.setEnabled(true);
            scanBtn.setEnabled(true);
            navigating = false;

            updateNavButtons();
            updateTitle(null);
        }

        private void updateNavButtons() {
            backBtn.setEnabled(historyIndex > 0);
            forwardBtn.setEnabled(historyIndex < history.size() - 1);
            historyLabel.setText((historyIndex + 1) + " / " + history.size());
        }

        private void updateTitle(String path) {
            // Not all Burp versions expose tab renaming, so we encode it in the status
            // as a best effort — the tab title itself stays "Verb Tamper"
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private String colourStatus(String text) { return text; }

        private void copyToClipboard(String text) {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(text), null);
        }

        private String swapMethod(String raw, String newMethod) {
            int firstSpace = raw.indexOf(' ');
            if (firstSpace == -1) return raw;
            return newMethod + raw.substring(firstSpace);
        }

        private String sanitiseHeaders(String raw) {
            String normalised = raw.replace("\r\n", "\n").replace("\r", "\n");
            String[] lines = normalised.split("\n", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (i > 0 && !line.isEmpty() && (line.charAt(0) == ' ' || line.charAt(0) == '\t')) {
                    if (out.length() >= 2) out.setLength(out.length() - 2);
                    out.append(line.trim()).append("\r\n");
                } else {
                    out.append(line).append("\r\n");
                }
            }
            String result = out.toString();
            result = result.replaceAll(
                "(Authorization: Bearer [A-Za-z0-9\\-_=+/]+)\\s*\\r?\\n([A-Za-z0-9\\-_=+/.]+)",
                "$1$2"
            );
            return result;
        }
    }
}
