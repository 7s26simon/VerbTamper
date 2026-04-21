package verbTamper;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
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
        this.tabRegistration = api.userInterface().registerSuiteTab("Verb Tamper", mainPanel);
        api.logging().logToOutput("Verb Tamper 1.2.1-f loaded.");
    }

    private void highlightProxyItem(HttpRequest req) {
        new Thread(() -> {
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                for (int i = history.size() - 1; i >= 0; i--) {
                    ProxyHttpRequestResponse item = history.get(i);
                    if (item.request().toString().equals(req.toString())) {
                        item.annotations().setHighlightColor(HighlightColor.ORANGE);
                        Thread.sleep(400L);
                        item.annotations().setHighlightColor(HighlightColor.NONE);
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }, "VerbTamper-Highlight").start();
    }

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

        private final DefaultListModel<String> tokenListModel;
        private final JList<String> tokenList;

        private HttpService currentService = null;
        private boolean loading = false;
        private final List<HistoryEntry> history = new ArrayList<>();
        private int historyIndex = -1;
        private boolean navigating = false;
        private String lastResponse = null;
        private String currentResponse = null;

        VerbTamperPanel() {
            super(new BorderLayout(8, 8));
            tokenListModel = new DefaultListModel<>();
            tokenList = new JList<>(tokenListModel);

            setBorder(new EmptyBorder(8, 8, 8, 8));

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

            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqScroll, respScroll);
            mainSplit.setResizeWeight(0.45);
            mainSplit.setDividerSize(6);

            backBtn = new JButton("\u25C0");
            backBtn.setToolTipText("Previous request");
            backBtn.setEnabled(false);
            backBtn.setMargin(new Insets(2, 6, 2, 6));

            forwardBtn = new JButton("\u25B6");
            forwardBtn.setToolTipText("Next request");
            forwardBtn.setEnabled(false);
            forwardBtn.setMargin(new Insets(2, 6, 2, 6));

            historyLabel = new JLabel("0 / 0");
            historyLabel.setForeground(Color.GRAY);
            historyLabel.setFont(historyLabel.getFont().deriveFont(11.0f));

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

            repeaterBtn = new JButton("\u2192 Repeater");
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

            JPanel authPanel = buildAuthPanel();
            JSplitPane outerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mainSplit, authPanel);
            outerSplit.setResizeWeight(0.78);
            outerSplit.setDividerSize(6);

            add(toolbar, BorderLayout.NORTH);
            add(outerSplit, BorderLayout.CENTER);

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

            // Repeater button reads the CURRENT textarea and dropdown state on
            // every click, so that changing the verb after a send (but before
            // clicking Repeater) correctly pushes the intended request to
            // Repeater rather than whatever was last sent.
            repeaterBtn.addActionListener(e -> {
                if (currentService == null) return;
                String rawText = sanitiseHeaders(requestArea.getText());
                String verb = (String) verbCombo.getSelectedItem();
                String updatedRaw = swapMethod(rawText, verb);
                try {
                    HttpRequest req = HttpRequest.httpRequest(currentService, updatedRaw);
                    api.repeater().sendToRepeater(req, "Verb Tamper - " + verb);
                    statusLabel.setText("Sent " + verb + " to Repeater");
                } catch (Exception ex) {
                    api.logging().logToError("[VerbTamper] Repeater send failure: " + ex);
                    statusLabel.setText("Repeater send failed: " + ex.getMessage());
                }
            });
        }

        private JSeparator makeSep() {
            JSeparator sep = new JSeparator(JSeparator.VERTICAL);
            sep.setPreferredSize(new Dimension(2, 22));
            return sep;
        }

        private JPanel buildAuthPanel() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(BorderFactory.createTitledBorder("Auth Tokens"));
            panel.setPreferredSize(new Dimension(220, 0));
            tokenList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            tokenList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            tokenList.setCellRenderer(new DefaultListCellRenderer() {
                @Override
                public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                    super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                    String s = value.toString();
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
            JButton addBtn = new JButton("Add");
            JButton applyBtn = new JButton("Apply");
            applyBtn.setBackground(new Color(60, 130, 60));
            applyBtn.setForeground(Color.WHITE);
            applyBtn.setOpaque(true);
            JButton editBtn = new JButton("Edit");
            JButton removeBtn = new JButton("Remove");

            JPanel btnRow = new JPanel(new GridLayout(2, 2, 3, 3));
            btnRow.add(addBtn);
            btnRow.add(applyBtn);
            btnRow.add(editBtn);
            btnRow.add(removeBtn);

            panel.add(scroll, BorderLayout.CENTER);
            panel.add(btnRow, BorderLayout.SOUTH);

            addBtn.addActionListener(e -> {
                JTextField labelField = new JTextField();
                JTextArea tokenField = new JTextArea(4, 30);
                tokenField.setLineWrap(true);
                tokenField.setWrapStyleWord(true);
                Object[] msg = {"Label (e.g. admin, hacker):", labelField, "Token (paste full JWT):", new JScrollPane(tokenField)};
                int r = JOptionPane.showConfirmDialog(panel, msg, "Add Auth Token", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (r == JOptionPane.OK_OPTION) {
                    String label = labelField.getText().trim();
                    String token = tokenField.getText().trim().replaceAll("\\s+", "");
                    if (!token.isEmpty()) {
                        String entry = label.isEmpty() ? token : label + "::" + token;
                        tokenListModel.addElement(entry);
                    }
                }
            });
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
                String updated;
                if (raw.contains("Authorization:")) {
                    updated = raw.replaceAll("(?m)^Authorization:.*$", "Authorization: Bearer " + token);
                } else {
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
            editBtn.addActionListener(e -> {
                int idx = tokenList.getSelectedIndex();
                if (idx < 0) {
                    statusLabel.setText("Select a token to edit");
                    return;
                }
                String existing = tokenListModel.getElementAt(idx);
                String existingLabel = existing.contains("::") ? existing.split("::", 2)[0] : "";
                String existingToken = existing.contains("::") ? existing.split("::", 2)[1] : existing;
                JTextField labelField = new JTextField(existingLabel);
                JTextArea tokenField = new JTextArea(4, 30);
                tokenField.setLineWrap(true);
                tokenField.setWrapStyleWord(true);
                tokenField.setText(existingToken);
                Object[] msg = {"Label:", labelField, "Token:", new JScrollPane(tokenField)};
                int r = JOptionPane.showConfirmDialog(panel, msg, "Edit Auth Token", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (r == JOptionPane.OK_OPTION) {
                    String label = labelField.getText().trim();
                    String token = tokenField.getText().trim().replaceAll("\\s+", "");
                    if (!token.isEmpty()) {
                        String entry = label.isEmpty() ? token : label + "::" + token;
                        tokenListModel.set(idx, entry);
                    }
                }
            });
            return panel;
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
            statusLabel.setText("Loaded \u2014 " + (currentService != null ? currentService.host() : "unknown"));
            sendBtn.setEnabled(true);
            scanBtn.setEnabled(true);
            repeaterBtn.setEnabled(true);
            copyRespBtn.setEnabled(false);
        }

        private void doSend() {
            if (currentService == null) return;

            String rawText = sanitiseHeaders(requestArea.getText());
            String selectedVerb = (String) verbCombo.getSelectedItem();
            final String updatedRaw = swapMethod(rawText, selectedVerb);

            api.logging().logToOutput("[VerbTamper] Sending " + selectedVerb + " to "
                    + currentService.host() + ":" + currentService.port()
                    + " (tls=" + currentService.secure() + ")");
            api.logging().logToOutput("[VerbTamper] Raw request (" + updatedRaw.length() + " bytes):\n" + updatedRaw);

            HttpRequest request;
            try {
                request = HttpRequest.httpRequest(currentService, updatedRaw);
            } catch (Exception ex) {
                statusLabel.setText("Parse error: " + ex.getMessage());
                api.logging().logToError("[VerbTamper] Parse failure: " + ex);
                return;
            }

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

                    final String responseText;
                    final String statusLine;

                    if (result == null) {
                        responseText = "(sendRequest returned null)";
                        statusLine = "no result";
                    } else if (result.response() == null) {
                        responseText = "(no response received -- request may have timed out or been dropped)";
                        statusLine = "no response";
                    } else {
                        // Prefer the raw byte array (reliable) over toString() (which
                        // some Montoya versions return empty for HTTP/2 responses).
                        String body;
                        try {
                            byte[] bytes = result.response().toByteArray().getBytes();
                            body = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                            api.logging().logToOutput("[VerbTamper] Response read via toByteArray: "
                                    + bytes.length + " bytes");
                        } catch (Exception byteErr) {
                            api.logging().logToError("[VerbTamper] toByteArray failed: " + byteErr);
                            body = result.response().toString();
                        }

                        // If byte path returned nothing useful, also try toString()
                        if (body == null || body.isEmpty()) {
                            String s = result.response().toString();
                            api.logging().logToOutput("[VerbTamper] toString fallback: "
                                    + (s == null ? "null" : s.length() + " chars"));
                            if (s != null && !s.isEmpty()) body = s;
                        }

                        // Final fallback: reconstruct from parts
                        if (body == null || body.isEmpty()) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(result.response().httpVersion()).append(' ')
                              .append(result.response().statusCode()).append(' ')
                              .append(result.response().reasonPhrase()).append("\r\n");
                            result.response().headers().forEach(h ->
                                sb.append(h.name()).append(": ").append(h.value()).append("\r\n"));
                            sb.append("\r\n").append(result.response().bodyToString());
                            body = sb.toString();
                            api.logging().logToOutput("[VerbTamper] Reconstructed response from parts: "
                                    + body.length() + " chars");
                        }

                        if (body == null || body.isEmpty()) {
                            responseText = "(empty response body)";
                            statusLine = "empty";
                        } else {
                            responseText = body;
                            statusLine = body.split("\r?\n", 2)[0];
                        }
                    }

                    api.logging().logToOutput("[VerbTamper] Got response: " + statusLine
                            + " (" + responseText.length() + " bytes)");

                    final HistoryEntry entry = new HistoryEntry(rawSnapshot, selectedVerb, responseText, currentService);

                    SwingUtilities.invokeLater(() -> {
                        lastResponse = currentResponse;
                        currentResponse = responseText;
                        diffBtn.setEnabled(lastResponse != null);
                        if (historyIndex < history.size() - 1) {
                            history.subList(historyIndex + 1, history.size()).clear();
                        }
                        history.add(entry);
                        historyIndex = history.size() - 1;
                        responseArea.setText(responseText);
                        responseArea.setCaretPosition(0);
                        statusLabel.setText(selectedVerb + " \u2192 " + statusLine);
                        copyRespBtn.setEnabled(true);
                        repeaterBtn.setEnabled(true);
                        updateNavButtons();
                    });
                } catch (Exception ex) {
                    api.logging().logToError("[VerbTamper] Send failure: " + ex);
                    SwingUtilities.invokeLater(() -> {
                        responseArea.setText("Error: " + ex.getMessage());
                        statusLabel.setText("Error: " + ex.getMessage());
                    });
                } finally {
                    SwingUtilities.invokeLater(() -> {
                        sendBtn.setEnabled(true);
                        sendBtn.setText("Send");
                    });
                }
            }, "VerbTamper-Send").start();
        }

        private void doScan() {
            if (currentService == null) return;
            final String rawText = sanitiseHeaders(requestArea.getText());
            boolean isHttp2 = rawText.split("\r?\n")[0].toUpperCase().contains("HTTP/2");
            final HttpMode mode = isHttp2 ? HttpMode.HTTP_2 : HttpMode.AUTO;

            final List<String> fullResponses = new ArrayList<>();
            String[] cols = {"Verb", "Status", "Length", "Response Preview"};
            DefaultTableModel model = new DefaultTableModel(cols, 0) {
                @Override
                public boolean isCellEditable(int r, int c) { return false; }
            };
            JTable table = new JTable(model);
            table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            table.setRowHeight(22);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.getColumnModel().getColumn(0).setPreferredWidth(70);
            table.getColumnModel().getColumn(1).setPreferredWidth(80);
            table.getColumnModel().getColumn(2).setPreferredWidth(70);
            table.getColumnModel().getColumn(3).setPreferredWidth(400);
            table.setToolTipText("Click a row to see the full response");
            table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object value, boolean sel, boolean focus, int row, int col) {
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

            JTextArea fullRespArea = new JTextArea();
            fullRespArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            fullRespArea.setEditable(false);
            fullRespArea.setBackground(new Color(28, 28, 28));
            fullRespArea.setForeground(Color.GRAY);
            fullRespArea.setText("Click a row above to view the full response");
            JScrollPane fullRespScroll = new JScrollPane(fullRespArea);
            fullRespScroll.setBorder(BorderFactory.createTitledBorder("Full Response"));
            table.getSelectionModel().addListSelectionListener(e -> {
                if (e.getValueIsAdjusting()) return;
                int row = table.getSelectedRow();
                if (row >= 0 && row < fullResponses.size()) {
                    fullRespArea.setForeground(new Color(180, 255, 180));
                    fullRespArea.setText(fullResponses.get(row));
                    fullRespArea.setCaretPosition(0);
                }
            });

            JButton copyFullBtn = new JButton("Copy Full Response");
            copyFullBtn.addActionListener(e -> {
                String txt = fullRespArea.getText();
                if (!txt.isEmpty() && !txt.startsWith("Click")) copyToClipboard(txt);
            });

            final JLabel scanStatus = new JLabel("Scanning 0 / " + VERBS.length + "...");
            scanStatus.setBorder(new EmptyBorder(4, 8, 4, 8));
            JPanel topRow = new JPanel(new BorderLayout());
            topRow.add(scanStatus, BorderLayout.CENTER);
            topRow.add(copyFullBtn, BorderLayout.EAST);

            JSplitPane scanSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), fullRespScroll);
            scanSplit.setResizeWeight(0.5);
            scanSplit.setDividerSize(6);
            SwingUtilities.invokeLater(() -> scanSplit.setDividerLocation(0.5));

            JDialog dialog = new JDialog();
            String path = rawText.split("\r?\n")[0].replaceAll("^\\w+\\s", "").replaceAll("\\s.*", "");
            dialog.setTitle("Scan All Verbs \u2014 " + (currentService != null ? currentService.host() : "") + path);
            dialog.setSize(800, 600);
            dialog.setLocationRelativeTo(null);
            dialog.setLayout(new BorderLayout(4, 4));
            dialog.add(topRow, BorderLayout.NORTH);
            dialog.add(scanSplit, BorderLayout.CENTER);
            dialog.setVisible(true);

            final AtomicInteger done = new AtomicInteger(0);
            for (final String verb : VERBS) {
                new Thread(() -> {
                    try {
                        String verbRaw = swapMethod(rawText, verb);
                        HttpRequest req = HttpRequest.httpRequest(currentService, verbRaw);
                        HttpRequestResponse result = api.http().sendRequest(req, mode);
                        String respText;
                        if (result.response() != null) {
                            try {
                                byte[] bytes = result.response().toByteArray().getBytes();
                                respText = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                                if (respText.isEmpty()) {
                                    StringBuilder sb = new StringBuilder();
                                    sb.append(result.response().httpVersion()).append(' ')
                                      .append(result.response().statusCode()).append(' ')
                                      .append(result.response().reasonPhrase()).append("\r\n");
                                    result.response().headers().forEach(h ->
                                        sb.append(h.name()).append(": ").append(h.value()).append("\r\n"));
                                    sb.append("\r\n").append(result.response().bodyToString());
                                    respText = sb.toString();
                                }
                            } catch (Exception readErr) {
                                respText = result.response().toString();
                            }
                        } else {
                            respText = "(no response)";
                        }
                        String[] respLines = respText.split("\r?\n");
                        String statusCode = respLines.length > 0 ? respLines[0].replaceAll("HTTP/\\S+\\s+", "").trim() : "?";
                        String statusNum = statusCode.length() >= 3 ? statusCode.substring(0, 3) : statusCode;
                        int length = respText.length();
                        String preview = "";
                        for (int j = respLines.length - 1; j >= 0; j--) {
                            if (!respLines[j].trim().isEmpty()) { preview = respLines[j]; break; }
                        }
                        if (preview.length() > 100) preview = preview.substring(0, 100) + "...";

                        final String fVerb = verb;
                        final String fStatus = statusNum;
                        final String fPreview = preview;
                        final String fResp = respText;
                        final int fLen = length;
                        SwingUtilities.invokeLater(() -> {
                            fullResponses.add(fResp);
                            model.addRow(new Object[]{fVerb, fStatus, "" + fLen, fPreview});
                            int n = done.incrementAndGet();
                            scanStatus.setText(n < VERBS.length
                                    ? "Scanning " + n + " / " + VERBS.length + "..."
                                    : "Done \u2014 click any row to see the full response");
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            fullResponses.add("Error: " + ex.getMessage());
                            model.addRow(new Object[]{verb, "ERR", "-", ex.getMessage()});
                            done.incrementAndGet();
                        });
                    }
                }, "VerbTamper-Scan-" + verb).start();
            }
        }

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
            legend.setFont(legend.getFont().deriveFont(11.0f));
            legend.setBorder(new EmptyBorder(4, 8, 4, 8));
            dialog.setLayout(new BorderLayout());
            dialog.add(legend, BorderLayout.NORTH);
            dialog.add(new JScrollPane(diffPane), BorderLayout.CENTER);
            dialog.setVisible(true);
        }

        private String escape(String s) {
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }

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
        }

        private void updateNavButtons() {
            backBtn.setEnabled(historyIndex > 0);
            forwardBtn.setEnabled(historyIndex < history.size() - 1);
            historyLabel.setText((historyIndex + 1) + " / " + history.size());
        }

        private void copyToClipboard(String text) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }

        private String swapMethod(String raw, String newMethod) {
            int firstSpace = raw.indexOf(' ');
            if (firstSpace == -1) return raw;
            return newMethod + raw.substring(firstSpace);
        }

        /**
         * Cleans up a raw request before handing it to Montoya.
         *
         *  - Splits the raw text into headers and body at the first blank line.
         *  - Normalises header line endings to CRLF (JTextArea stores \n only).
         *  - Handles folded header continuation lines (leading space/tab).
         *  - Stitches back together JWTs that wrapped onto a second line.
         *  - Rebuilds the request as: headers + CRLF CRLF + body, so the
         *    headers section is always correctly terminated.
         *
         * Operating on the headers block in isolation is important: the
         * sanitisation rules (CRLF normalisation, folded-header joining,
         * Bearer-token stitching) would otherwise corrupt JSON bodies that
         * happen to contain patterns the regex matches.
         */
        private String sanitiseHeaders(String raw) {
            String normalised = raw.replace("\r\n", "\n").replace("\r", "\n");

            // Split at the first blank line — everything before it is headers,
            // everything after is the body (which we leave untouched).
            String headerPart;
            String bodyPart;
            int blank = normalised.indexOf("\n\n");
            if (blank == -1) {
                headerPart = normalised;
                bodyPart = "";
            } else {
                headerPart = normalised.substring(0, blank);
                bodyPart = normalised.substring(blank + 2);
            }

            // Strip any trailing newlines from the header part. Without this,
            // text entered in the JTextArea with a trailing Enter keystroke
            // (e.g. after pasting) would produce an empty final line that
            // survives the rebuild as an extra \r\n, and then the terminator
            // we append at the end stacks on top of it producing \r\n\r\n\r\n.
            // Express (and most servers) reject that triple-CRLF as a malformed
            // request with 400 Bad Request.
            while (headerPart.endsWith("\n")) {
                headerPart = headerPart.substring(0, headerPart.length() - 1);
            }

            // Rebuild headers with CRLF line endings and continuation folding.
            String[] lines = headerPart.split("\n", -1);
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (i > 0 && !line.isEmpty() && (line.charAt(0) == ' ' || line.charAt(0) == '\t')) {
                    // Folded header continuation: strip the trailing CRLF
                    // we just wrote and append the trimmed continuation.
                    if (out.length() >= 2) out.setLength(out.length() - 2);
                    out.append(line.trim()).append("\r\n");
                } else {
                    out.append(line).append("\r\n");
                }
            }
            String headers = out.toString();

            // Stitch Bearer tokens that wrapped onto a following line.
            //
            // The tricky part: we must only merge when the second line is a
            // genuine continuation of the JWT, NOT the start of the next
            // header. The original v1.2 regex didn't guard this and would
            // happily merge "Authorization: Bearer xxx\r\nAccept-Language:"
            // into "Authorization: Bearer xxxAccept-Language:" -- producing
            // a malformed header and a 400 Bad Request from the server.
            //
            // Guard: the second captured group must be followed by \r\n
            // (meaning it's the WHOLE next line), not by ':' (which would
            // mean it's a header name).
            headers = headers.replaceAll(
                    "(?m)^(Authorization: Bearer [A-Za-z0-9\\-_=+/]+)\\r\\n([A-Za-z0-9\\-_=+/.]+)\\r\\n",
                    "$1$2\r\n");

            // Fix Content-Length to match the actual body size. This is what
            // prevents 502 Bad Gateway when the user changes the verb and a
            // stale Content-Length from the original request is left behind
            // (e.g. PUT -> GET leaves "Content-Length: 133" with no body,
            // causing the upstream to hang waiting for bytes that never arrive).
            int actualBodyLength = bodyPart.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            boolean hasCL = headers.matches("(?is).*(^|\\r\\n)Content-Length:.*");
            if (hasCL) {
                // Header exists: rewrite it to the correct length (including 0).
                headers = headers.replaceAll(
                        "(?im)^Content-Length:.*\\r\\n",
                        "Content-Length: " + actualBodyLength + "\r\n");
            } else if (actualBodyLength > 0) {
                // No existing header but we have a body: add Content-Length
                // right before the terminator. Insert after the last header.
                headers = headers + "Content-Length: " + actualBodyLength + "\r\n";
            }
            // If there's no Content-Length header and no body, leave it alone
            // -- same as what browsers do for GET.

            // headers already ends with \r\n from the loop above, so adding
            // one more \r\n gives us the required blank-line terminator.
            return headers + "\r\n" + bodyPart;
        }
    }
}
