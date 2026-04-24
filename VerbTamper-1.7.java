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

    /** Sentinel item shown last in the verb dropdown. Picking it triggers a prompt
     *  for a non-standard / custom verb (e.g. POSTX, PROPFIND, FOOBAR) which then
     *  replaces this sentinel as the selected dropdown item. The scan-all-verbs
     *  loop deliberately does NOT include the custom verb -- the scan is "try the
     *  7 real verbs and see what shakes loose", and adding arbitrary custom verbs
     *  to it changes what the scan means.
     */
    private static final String CUSTOM_VERB_LABEL = "Custom\u2026";

    /**
     * Catalog of bypass headers to expose in the header dropdown. Each entry
     * knows: the human-readable label, the header name, a default value, and
     * whether picking it should also switch the verb dropdown (for method
     * override entries -- the whole point is to send the outer verb as POST).
     */
    private static class BypassHeader {
        final String category;
        final String name;
        final String defaultValue;
        final String overrideVerb;   // if non-null, flip the verb combo to this when inserting

        BypassHeader(String category, String name, String defaultValue, String overrideVerb) {
            this.category = category;
            this.name = name;
            this.defaultValue = defaultValue;
            this.overrideVerb = overrideVerb;
        }

        /** Label shown in the dropdown. */
        String label() {
            return "[" + category + "] " + name + ": " + defaultValue;
        }
    }

    private static final BypassHeader[] BYPASS_HEADERS = {
            // Method override -- smuggle a verb through a POST-only endpoint.
            new BypassHeader("method",  "X-HTTP-Method-Override", "DELETE", "POST"),
            new BypassHeader("method",  "X-HTTP-Method-Override", "PUT",    "POST"),
            new BypassHeader("method",  "X-HTTP-Method-Override", "PATCH",  "POST"),
            new BypassHeader("method",  "X-HTTP-Method",          "DELETE", "POST"),
            new BypassHeader("method",  "X-Method-Override",      "DELETE", "POST"),
            // IP spoofing / client identity -- does the server trust upstream headers?
            new BypassHeader("ip",      "X-Forwarded-For",        "127.0.0.1", null),
            new BypassHeader("ip",      "X-Real-IP",              "127.0.0.1", null),
            new BypassHeader("ip",      "X-Originating-IP",       "127.0.0.1", null),
            new BypassHeader("ip",      "X-Remote-IP",            "127.0.0.1", null),
            new BypassHeader("ip",      "X-Client-IP",            "127.0.0.1", null),
            new BypassHeader("ip",      "X-Host",                 "localhost", null),
            new BypassHeader("ip",      "X-Forwarded-Host",       "localhost", null),
            // URL rewriting -- does the proxy rewrite the path before the app sees it?
            new BypassHeader("url",     "X-Original-URL",         "/admin", null),
            new BypassHeader("url",     "X-Rewrite-URL",          "/admin", null),
            new BypassHeader("url",     "X-Override-URL",         "/admin", null),
    };

    private VerbTamperPanel mainPanel;
    private Registration tabRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.mainPanel = new VerbTamperPanel();
        this.historyPanel = new ScanHistoryPanel();
        this.sendHistoryPanel = new SendHistoryPanel();

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Scanner", mainPanel);
        tabs.addTab("Send History", sendHistoryPanel);
        tabs.addTab("Scan History", historyPanel);

        api.userInterface().registerContextMenuItemsProvider(new VerbContextMenuProvider());
        this.tabRegistration = api.userInterface().registerSuiteTab("Verb Tamper", tabs);
        api.logging().logToOutput("Verb Tamper 1.7 loaded.");
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

    /**
     * Renders a scan results dialog for a ScanSession. Used both for live scans
     * (live=true, rows populate as workers finish) and for replays from the
     * History tab (live=false, rows are pre-populated from session.records).
     *
     * Returns the table model so live-scan callers can append rows to it;
     * replay callers can ignore the return value.
     */
    private DefaultTableModel showScanResultsDialog(ScanSession session, boolean live) {
        String[] cols = {"Verb", "Status", "Length", "Response Preview"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
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
            if (row >= 0 && row < session.records.size()) {
                fullRespArea.setForeground(new Color(180, 255, 180));
                fullRespArea.setText(session.records.get(row).fullResponse);
                fullRespArea.setCaretPosition(0);
            }
        });

        JButton copyFullBtn = new JButton("Copy Full Response");
        copyFullBtn.addActionListener(e -> {
            String txt = fullRespArea.getText();
            if (!txt.isEmpty() && !txt.startsWith("Click")) {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(txt), null);
            }
        });

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.setToolTipText("Save this scan's results as a CSV file");
        exportBtn.addActionListener(e -> exportScanToCsv(session));

        final JLabel scanStatus = new JLabel(live
                ? "Scanning 0 / " + session.expectedCount + "..."
                : "Replay \u2014 " + session.records.size() + " results");
        scanStatus.setBorder(new EmptyBorder(4, 8, 4, 8));

        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        rightButtons.add(exportBtn);
        rightButtons.add(copyFullBtn);

        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(scanStatus, BorderLayout.CENTER);
        topRow.add(rightButtons, BorderLayout.EAST);

        JSplitPane scanSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), fullRespScroll);
        scanSplit.setResizeWeight(0.5);
        scanSplit.setDividerSize(6);
        SwingUtilities.invokeLater(() -> scanSplit.setDividerLocation(0.5));

        JDialog dialog = new JDialog();
        dialog.setTitle("Scan All Verbs \u2014 " + session.displayTitle());
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(null);
        dialog.setLayout(new BorderLayout(4, 4));
        dialog.add(topRow, BorderLayout.NORTH);
        dialog.add(scanSplit, BorderLayout.CENTER);
        dialog.setVisible(true);

        // Replay mode: populate table immediately from existing records.
        if (!live) {
            for (ScanRecord rec : session.records) {
                model.addRow(new Object[]{rec.verb, rec.status, "" + rec.length, rec.preview});
            }
        }

        // Live mode: update the status label as rows arrive.
        if (live) {
            model.addTableModelListener(e -> {
                int n = model.getRowCount();
                scanStatus.setText(n < session.expectedCount
                        ? "Scanning " + n + " / " + session.expectedCount + "..."
                        : "Done \u2014 click any row to see the full response");
            });
        }

        return model;
    }

    /**
     * Prompt for a file and write a single scan session's results as CSV.
     * Columns: Verb, Status, Length, Preview, FullResponse.
     */
    private void exportScanToCsv(ScanSession session) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export scan to CSV");
        String suggested = "verbtamper-scan-" + session.host.replaceAll("[^a-zA-Z0-9.-]", "_")
                + "-" + session.timestampMs + ".csv";
        chooser.setSelectedFile(new java.io.File(suggested));
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        java.io.File f = chooser.getSelectedFile();
        try (java.io.PrintWriter out = new java.io.PrintWriter(
                new java.io.OutputStreamWriter(new java.io.FileOutputStream(f), java.nio.charset.StandardCharsets.UTF_8))) {
            out.println("Verb,Status,Length,Preview,FullResponse");
            for (ScanRecord r : session.records) {
                out.print(csvEscape(r.verb));
                out.print(',');
                out.print(csvEscape(r.status));
                out.print(',');
                out.print(r.length);
                out.print(',');
                out.print(csvEscape(r.preview));
                out.print(',');
                out.print(csvEscape(r.fullResponse));
                out.println();
            }
            api.logging().logToOutput("[VerbTamper] Exported scan to " + f.getAbsolutePath());
        } catch (Exception ex) {
            api.logging().logToError("[VerbTamper] CSV export failed: " + ex);
            JOptionPane.showMessageDialog(null, "Export failed: " + ex.getMessage(),
                    "Export error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Prompt for a file and write ALL scan sessions as a flat CSV, one row
     * per verb-attempt. Useful for pivoting in Excel across hosts / roles.
     */
    private void exportAllHistoryToCsv(List<ScanSession> sessions) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export all scan history to CSV");
        chooser.setSelectedFile(new java.io.File(
                "verbtamper-history-" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        java.io.File f = chooser.getSelectedFile();
        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        try (java.io.PrintWriter out = new java.io.PrintWriter(
                new java.io.OutputStreamWriter(new java.io.FileOutputStream(f), java.nio.charset.StandardCharsets.UTF_8))) {
            out.println("Timestamp,Host,Path,OriginalVerb,VerbTried,Status,Length,Preview");
            for (ScanSession s : sessions) {
                String ts = fmt.format(new java.util.Date(s.timestampMs));
                for (ScanRecord r : s.records) {
                    out.print(csvEscape(ts));
                    out.print(',');
                    out.print(csvEscape(s.host));
                    out.print(',');
                    out.print(csvEscape(s.path));
                    out.print(',');
                    out.print(csvEscape(s.originalVerb));
                    out.print(',');
                    out.print(csvEscape(r.verb));
                    out.print(',');
                    out.print(csvEscape(r.status));
                    out.print(',');
                    out.print(r.length);
                    out.print(',');
                    out.print(csvEscape(r.preview));
                    out.println();
                }
            }
            api.logging().logToOutput("[VerbTamper] Exported " + sessions.size()
                    + " scans to " + f.getAbsolutePath());
        } catch (Exception ex) {
            api.logging().logToError("[VerbTamper] History export failed: " + ex);
            JOptionPane.showMessageDialog(null, "Export failed: " + ex.getMessage(),
                    "Export error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Quote and escape a CSV field per RFC 4180. */
    private static String csvEscape(String s) {
        if (s == null) return "";
        boolean needsQuote = s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r");
        String escaped = s.replace("\"", "\"\"");
        return needsQuote ? "\"" + escaped + "\"" : escaped;
    }

    private static class HistoryEntry {
        final long timestampMs;
        final String requestText;
        final String verb;
        final String responseText;
        final HttpService service;

        HistoryEntry(String requestText, String verb, String responseText, HttpService service) {
            this.timestampMs = System.currentTimeMillis();
            this.requestText = requestText;
            this.verb = verb;
            this.responseText = responseText;
            this.service = service;
        }

        /** Extract the path from the first line of the stored request text. */
        String path() {
            if (requestText == null || requestText.isEmpty()) return "";
            String firstLine = requestText.split("\r?\n", 2)[0];
            // "VERB /path HTTP/2" -> "/path"
            String afterVerb = firstLine.replaceFirst("^\\S+\\s+", "");
            int sp = afterVerb.indexOf(' ');
            return sp >= 0 ? afterVerb.substring(0, sp) : afterVerb;
        }

        /** Pull the status code out of the stored response text, or "-" if unknown. */
        String status() {
            if (responseText == null || responseText.isEmpty()) return "-";
            String firstLine = responseText.split("\r?\n", 2)[0];
            // "HTTP/2 200 OK" -> "200"
            String[] parts = firstLine.split("\\s+");
            return parts.length >= 2 ? parts[1] : "-";
        }

        int responseLength() {
            return responseText == null ? 0 : responseText.length();
        }
    }

    /** One row of a Scan All Verbs result: the outcome of trying one verb. */
    private static class ScanRecord {
        final String verb;
        final String status;     // e.g. "200", "403", "ERR"
        final int length;
        final String preview;
        final String fullResponse;

        ScanRecord(String verb, String status, int length, String preview, String fullResponse) {
            this.verb = verb;
            this.status = status;
            this.length = length;
            this.preview = preview;
            this.fullResponse = fullResponse;
        }
    }

    /** One complete scan run: the request that was scanned + every verb's result. */
    private static class ScanSession {
        final long timestampMs;
        final String host;
        final String path;
        final String originalVerb;
        // Total number of verbs the scan will attempt -- tracked separately
        // from records.size() so the live progress label can show "N of M"
        // before all the workers have completed.
        final int expectedCount;
        final List<ScanRecord> records = new ArrayList<>();

        ScanSession(String host, String path, String originalVerb, int expectedCount) {
            this.timestampMs = System.currentTimeMillis();
            this.host = host;
            this.path = path;
            this.originalVerb = originalVerb;
            this.expectedCount = expectedCount;
        }

        String displayTitle() {
            return host + path;
        }
    }

    // Shared across tabs: all scans performed this Burp session.
    private final List<ScanSession> scanHistory = new ArrayList<>();
    private ScanHistoryPanel historyPanel;
    private SendHistoryPanel sendHistoryPanel;

    /**
     * The "Scan History" tab: a table listing every scan run this session,
     * with buttons to re-open a past scan, delete an entry, clear all, and
     * export the whole history as CSV.
     */
    private class ScanHistoryPanel extends JPanel {
        private final DefaultTableModel model;
        private final JTable table;
        private final JLabel statusLabel;
        private final java.text.SimpleDateFormat tsFmt =
                new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        ScanHistoryPanel() {
            super(new BorderLayout(8, 8));
            setBorder(new EmptyBorder(8, 8, 8, 8));

            String[] cols = {"Time", "Host", "Path", "Loaded Verb", "# Verbs", "Notable"};
            model = new DefaultTableModel(cols, 0) {
                @Override public boolean isCellEditable(int r, int c) { return false; }
            };
            table = new JTable(model);
            table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            table.setRowHeight(22);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.getColumnModel().getColumn(0).setPreferredWidth(140);
            table.getColumnModel().getColumn(1).setPreferredWidth(240);
            table.getColumnModel().getColumn(2).setPreferredWidth(240);
            table.getColumnModel().getColumn(3).setPreferredWidth(80);
            table.getColumnModel().getColumn(4).setPreferredWidth(60);
            table.getColumnModel().getColumn(5).setPreferredWidth(200);
            // Double-click a row to reopen the scan.
            table.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                    if (e.getClickCount() == 2) openSelected();
                }
            });

            JScrollPane scroll = new JScrollPane(table);
            scroll.setBorder(BorderFactory.createTitledBorder("Scan History (this session)"));

            JButton openBtn = new JButton("Open");
            openBtn.setToolTipText("Reopen the selected scan's results");
            openBtn.addActionListener(e -> openSelected());

            JButton deleteBtn = new JButton("Delete");
            deleteBtn.addActionListener(e -> {
                int row = table.getSelectedRow();
                if (row < 0 || row >= scanHistory.size()) return;
                scanHistory.remove(row);
                refresh();
            });

            JButton clearBtn = new JButton("Clear All");
            clearBtn.setForeground(new Color(180, 60, 60));
            clearBtn.addActionListener(e -> {
                if (scanHistory.isEmpty()) return;
                int r = JOptionPane.showConfirmDialog(this,
                        "Delete all " + scanHistory.size() + " scan(s) from history?",
                        "Clear scan history",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
                if (r == JOptionPane.OK_OPTION) {
                    scanHistory.clear();
                    refresh();
                }
            });

            statusLabel = new JLabel("No scans yet \u2014 run Scan All Verbs from the Scanner tab");
            statusLabel.setForeground(Color.GRAY);

            JButton exportAllBtn = new JButton("Export All to CSV");
            exportAllBtn.setBackground(new Color(60, 130, 60));
            exportAllBtn.setForeground(Color.WHITE);
            exportAllBtn.setOpaque(true);
            exportAllBtn.addActionListener(e -> {
                if (scanHistory.isEmpty()) {
                    statusLabel.setText("No scans to export");
                    return;
                }
                exportAllHistoryToCsv(new ArrayList<>(scanHistory));
            });

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            buttons.add(openBtn);
            buttons.add(deleteBtn);
            buttons.add(clearBtn);
            buttons.add(new JSeparator(JSeparator.VERTICAL) {{
                setPreferredSize(new Dimension(2, 22));
            }});
            buttons.add(exportAllBtn);
            buttons.add(statusLabel);

            add(buttons, BorderLayout.NORTH);
            add(scroll, BorderLayout.CENTER);
        }

        private void openSelected() {
            int row = table.getSelectedRow();
            if (row < 0 || row >= scanHistory.size()) return;
            showScanResultsDialog(scanHistory.get(row), false);
        }

        /**
         * Flags a scan as "notable" if there's meaningful variation across verbs --
         * a mix of 2xx and 4xx responses is usually what we're looking for in a
         * BFLA check.
         */
        private String notableFlag(ScanSession s) {
            boolean has2xx = false, has4xx = false, has5xx = false;
            for (ScanRecord r : s.records) {
                if (r.status.startsWith("2")) has2xx = true;
                else if (r.status.startsWith("4")) has4xx = true;
                else if (r.status.startsWith("5")) has5xx = true;
            }
            if (has2xx && has4xx) return "\u2605 2xx + 4xx mix";
            if (has2xx && has5xx) return "2xx + 5xx mix";
            return "";
        }

        void refresh() {
            SwingUtilities.invokeLater(() -> {
                model.setRowCount(0);
                for (ScanSession s : scanHistory) {
                    model.addRow(new Object[]{
                            tsFmt.format(new java.util.Date(s.timestampMs)),
                            s.host,
                            s.path,
                            s.originalVerb,
                            s.records.size(),
                            notableFlag(s),
                    });
                }
                statusLabel.setText(scanHistory.isEmpty()
                        ? "No scans yet \u2014 run Scan All Verbs from the Scanner tab"
                        : scanHistory.size() + " scan(s) in history");
            });
        }
    }

    /**
     * The "Send History" tab: a table of every individual request sent via
     * the Scanner tab's Send button. Double-click an entry to load it back
     * into the Scanner editor.
     */
    private class SendHistoryPanel extends JPanel {
        private final DefaultTableModel model;
        private final JTable table;
        private final JLabel statusLabel;
        private final java.text.SimpleDateFormat tsFmt =
                new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        SendHistoryPanel() {
            super(new BorderLayout(8, 8));
            setBorder(new EmptyBorder(8, 8, 8, 8));

            String[] cols = {"#", "Time", "Verb", "Host", "Path", "Status", "Length"};
            model = new DefaultTableModel(cols, 0) {
                @Override public boolean isCellEditable(int r, int c) { return false; }
            };
            table = new JTable(model);
            table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            table.setRowHeight(22);
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.getColumnModel().getColumn(0).setPreferredWidth(40);
            table.getColumnModel().getColumn(1).setPreferredWidth(140);
            table.getColumnModel().getColumn(2).setPreferredWidth(70);
            table.getColumnModel().getColumn(3).setPreferredWidth(240);
            table.getColumnModel().getColumn(4).setPreferredWidth(280);
            table.getColumnModel().getColumn(5).setPreferredWidth(60);
            table.getColumnModel().getColumn(6).setPreferredWidth(70);

            // Colour rows by status class to match the scan dialog.
            table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable t, Object value, boolean sel, boolean focus, int row, int col) {
                    super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                    String status = (String) t.getModel().getValueAt(row, 5);
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

            // Double-click loads the entry back into the Scanner tab.
            table.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                    if (e.getClickCount() == 2) openSelected();
                }
            });

            JScrollPane scroll = new JScrollPane(table);
            scroll.setBorder(BorderFactory.createTitledBorder("Send History (this session)"));

            JButton openBtn = new JButton("Open in Scanner");
            openBtn.setToolTipText("Load this entry back into the Scanner tab's editor");
            openBtn.addActionListener(e -> openSelected());

            JButton viewRespBtn = new JButton("View Response");
            viewRespBtn.setToolTipText("Show the full response for this entry");
            viewRespBtn.addActionListener(e -> {
                int row = table.getSelectedRow();
                List<HistoryEntry> sends = mainPanel.sendHistory();
                if (row < 0 || row >= sends.size()) return;
                showResponseDialog(sends.get(row));
            });

            JButton deleteBtn = new JButton("Delete");
            deleteBtn.addActionListener(e -> {
                int row = table.getSelectedRow();
                List<HistoryEntry> sends = mainPanel.sendHistory();
                if (row < 0 || row >= sends.size()) return;
                sends.remove(row);
                // Also bump the Scanner tab's index if we deleted behind it.
                mainPanel.onSendHistoryExternallyModified();
                refresh();
            });

            JButton clearBtn = new JButton("Clear All");
            clearBtn.setForeground(new Color(180, 60, 60));
            clearBtn.addActionListener(e -> {
                List<HistoryEntry> sends = mainPanel.sendHistory();
                if (sends.isEmpty()) return;
                int r = JOptionPane.showConfirmDialog(this,
                        "Delete all " + sends.size() + " send(s) from history?",
                        "Clear send history",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
                if (r == JOptionPane.OK_OPTION) {
                    sends.clear();
                    mainPanel.onSendHistoryExternallyModified();
                    refresh();
                }
            });

            statusLabel = new JLabel("No sends yet \u2014 use the Scanner tab's Send button");
            statusLabel.setForeground(Color.GRAY);

            JButton exportBtn = new JButton("Export All to CSV");
            exportBtn.setBackground(new Color(60, 130, 60));
            exportBtn.setForeground(Color.WHITE);
            exportBtn.setOpaque(true);
            exportBtn.addActionListener(e -> {
                List<HistoryEntry> sends = mainPanel.sendHistory();
                if (sends.isEmpty()) {
                    statusLabel.setText("No sends to export");
                    return;
                }
                exportSendHistoryToCsv(new ArrayList<>(sends));
            });

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            buttons.add(openBtn);
            buttons.add(viewRespBtn);
            buttons.add(deleteBtn);
            buttons.add(clearBtn);
            buttons.add(new JSeparator(JSeparator.VERTICAL) {{
                setPreferredSize(new Dimension(2, 22));
            }});
            buttons.add(exportBtn);
            buttons.add(statusLabel);

            add(buttons, BorderLayout.NORTH);
            add(scroll, BorderLayout.CENTER);
        }

        private void openSelected() {
            int row = table.getSelectedRow();
            List<HistoryEntry> sends = mainPanel.sendHistory();
            if (row < 0 || row >= sends.size()) return;
            mainPanel.loadHistoryEntry(row);
        }

        /** Small read-only dialog showing the full response for a send. */
        private void showResponseDialog(HistoryEntry entry) {
            JDialog dialog = new JDialog();
            dialog.setTitle(entry.verb + " " + entry.path() + " \u2014 " + entry.status());
            dialog.setSize(800, 600);
            dialog.setLocationRelativeTo(null);
            JTextArea area = new JTextArea(entry.responseText);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            area.setEditable(false);
            area.setBackground(new Color(28, 28, 28));
            area.setForeground(new Color(180, 255, 180));
            area.setCaretPosition(0);
            dialog.add(new JScrollPane(area), BorderLayout.CENTER);
            JButton copyBtn = new JButton("Copy");
            copyBtn.addActionListener(e ->
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                            new StringSelection(entry.responseText), null));
            JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            bottom.add(copyBtn);
            dialog.add(bottom, BorderLayout.SOUTH);
            dialog.setVisible(true);
        }

        void refresh() {
            SwingUtilities.invokeLater(() -> {
                List<HistoryEntry> sends = mainPanel.sendHistory();
                model.setRowCount(0);
                for (int i = 0; i < sends.size(); i++) {
                    HistoryEntry h = sends.get(i);
                    String host = h.service != null ? h.service.host() : "";
                    model.addRow(new Object[]{
                            i + 1,
                            tsFmt.format(new java.util.Date(h.timestampMs)),
                            h.verb,
                            host,
                            h.path(),
                            h.status(),
                            "" + h.responseLength(),
                    });
                }
                statusLabel.setText(sends.isEmpty()
                        ? "No sends yet \u2014 use the Scanner tab's Send button"
                        : sends.size() + " send(s) in history");
            });
        }
    }

    /**
     * Prompt for a file and write send history as CSV. Summary columns only
     * (no full request/response bodies to keep the output spreadsheet-friendly).
     */
    private void exportSendHistoryToCsv(List<HistoryEntry> sends) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Export send history to CSV");
        chooser.setSelectedFile(new java.io.File(
                "verbtamper-sends-" + System.currentTimeMillis() + ".csv"));
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        java.io.File f = chooser.getSelectedFile();
        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        try (java.io.PrintWriter out = new java.io.PrintWriter(
                new java.io.OutputStreamWriter(new java.io.FileOutputStream(f), java.nio.charset.StandardCharsets.UTF_8))) {
            out.println("Timestamp,Host,Path,Verb,Status,ResponseLength");
            for (HistoryEntry h : sends) {
                String host = h.service != null ? h.service.host() : "";
                out.print(csvEscape(fmt.format(new java.util.Date(h.timestampMs))));
                out.print(',');
                out.print(csvEscape(host));
                out.print(',');
                out.print(csvEscape(h.path()));
                out.print(',');
                out.print(csvEscape(h.verb));
                out.print(',');
                out.print(csvEscape(h.status()));
                out.print(',');
                out.print(h.responseLength());
                out.println();
            }
            api.logging().logToOutput("[VerbTamper] Exported " + sends.size()
                    + " sends to " + f.getAbsolutePath());
        } catch (Exception ex) {
            api.logging().logToError("[VerbTamper] Send history export failed: " + ex);
            JOptionPane.showMessageDialog(null, "Export failed: " + ex.getMessage(),
                    "Export error", JOptionPane.ERROR_MESSAGE);
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
        private final JComboBox<String> verbCombo;        private final JButton sendBtn;
        private final JButton scanBtn;
        private final JButton repeaterBtn;
        private final JButton backBtn;
        private final JButton forwardBtn;
        private final JButton clearBtn;
        private final JButton copyReqBtn;
        private final JButton copyRespBtn;
        private final JButton diffBtn;
        private final JButton followRedirectBtn;
        private final JLabel statusLabel;
        private final JLabel historyLabel;

        private final DefaultListModel<String> tokenListModel;
        private final JList<String> tokenList;

        private HttpService currentService = null;
        private boolean loading = false;
        // Tracks the previous selection so we can revert if the user picks
        // "Custom..." and then cancels the prompt dialog.
        private int lastSelectedVerbIndex = 0;
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
            attachUrlContextMenu(requestArea, false);
            JScrollPane reqScroll = new JScrollPane(requestArea);
            reqScroll.setBorder(BorderFactory.createTitledBorder("Request (editable)"));

            responseArea = new JTextArea();
            responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            responseArea.setEditable(false);
            responseArea.setBackground(new Color(28, 28, 28));
            responseArea.setForeground(new Color(180, 255, 180));
            attachUrlContextMenu(responseArea, true);
            JScrollPane respScroll = new JScrollPane(responseArea);
            respScroll.setBorder(BorderFactory.createTitledBorder("Response"));

            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqScroll, respScroll);
            mainSplit.setResizeWeight(0.5);
            mainSplit.setDividerSize(6);
            // Force a 50/50 initial split. Timing is tricky: at construction
            // time the pane has no height yet, so setDividerLocation(0.5)
            // resolves to zero pixels. Burp also doesn't realise the tab
            // until the user clicks it, so invokeLater isn't late enough.
            // The reliable fix is a ComponentListener on the split pane
            // itself -- the first time it gets a non-trivial height, set
            // the divider to half of that and remove the listener so we
            // don't fight the user's own drags afterwards.
            mainSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
                private boolean done = false;
                @Override
                public void componentResized(java.awt.event.ComponentEvent e) {
                    if (done) return;
                    int h = mainSplit.getHeight();
                    if (h > 100) {
                        mainSplit.setDividerLocation(h / 2);
                        done = true;
                        mainSplit.removeComponentListener(this);
                    }
                }
            });

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

            verbCombo = new JComboBox<>(buildInitialVerbItems());
            verbCombo.setFont(verbCombo.getFont().deriveFont(Font.BOLD));
            verbCombo.setPreferredSize(new Dimension(120, 28));

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

            followRedirectBtn = new JButton("Follow Redirect");
            followRedirectBtn.setToolTipText("Send a GET to the Location header of the current 3xx response");
            followRedirectBtn.setEnabled(false);

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
            toolbar.add(followRedirectBtn);
            toolbar.add(copyReqBtn);
            toolbar.add(copyRespBtn);
            toolbar.add(clearBtn);
            toolbar.add(statusLabel);

            // Second toolbar row: bypass header inserter. A single dropdown
            // with a placeholder-first design -- picking a real entry inserts
            // the header immediately and resets the dropdown to the placeholder
            // so you can quickly add several.
            JPanel headerBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 3));
            String placeholder = "Add bypass header\u2026";
            List<String> items = new ArrayList<>();
            items.add(placeholder);
            for (BypassHeader h : BYPASS_HEADERS) items.add(h.label());
            JComboBox<String> headerCombo = new JComboBox<>(items.toArray(new String[0]));
            headerCombo.setPreferredSize(new Dimension(340, 26));
            headerCombo.setToolTipText("Pick a header to insert into the request. "
                    + "Method-override entries also switch the verb to POST.");
            headerCombo.addActionListener(e -> {
                int idx = headerCombo.getSelectedIndex();
                if (idx <= 0) return; // placeholder selected
                BypassHeader h = BYPASS_HEADERS[idx - 1];
                insertOrReplaceHeader(h);
                // Reset to placeholder so the next pick fires the listener again.
                headerCombo.setSelectedIndex(0);
            });
            JLabel headerHint = new JLabel("Headers:");
            headerHint.setFont(headerHint.getFont().deriveFont(11.0f));
            headerHint.setForeground(Color.GRAY);
            headerBar.add(headerHint);
            headerBar.add(headerCombo);

            JPanel northStack = new JPanel(new GridLayout(2, 1));
            northStack.add(toolbar);
            northStack.add(headerBar);

            JPanel authPanel = buildAuthPanel();
            JSplitPane outerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mainSplit, authPanel);
            outerSplit.setResizeWeight(0.78);
            outerSplit.setDividerSize(6);

            add(northStack, BorderLayout.NORTH);
            add(outerSplit, BorderLayout.CENTER);

            verbCombo.addActionListener(e -> {
                if (loading || navigating) return;
                String selected = (String) verbCombo.getSelectedItem();
                if (selected == null) return;
                if (CUSTOM_VERB_LABEL.equals(selected)) {
                    // Don't update lastSelectedVerbIndex here -- the prompt helper
                    // either commits a new selection or reverts to the previous one.
                    handleCustomVerbPicked();
                    return;
                }
                lastSelectedVerbIndex = verbCombo.getSelectedIndex();
                String text = requestArea.getText();
                if (text.isEmpty() || text.startsWith("Right-click")) return;
                String updated = swapMethod(text, selected);
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
                followRedirectBtn.setEnabled(false);
                currentService = null;
                // Drop any custom verbs the user added via "Custom..." so the
                // dropdown resets to its initial state. Anything past the
                // standard verbs that isn't the sentinel is user-entered.
                loading = true;
                DefaultComboBoxModel<String> model =
                        (DefaultComboBoxModel<String>) verbCombo.getModel();
                for (int i = model.getSize() - 1; i >= VERBS.length; i--) {
                    String item = model.getElementAt(i);
                    if (!CUSTOM_VERB_LABEL.equals(item)) model.removeElementAt(i);
                }
                verbCombo.setSelectedIndex(0);
                lastSelectedVerbIndex = 0;
                loading = false;
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
            followRedirectBtn.addActionListener(e -> doFollowRedirect());

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
            selectVerbInCombo(method);
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
                        followRedirectBtn.setEnabled(isFollowableRedirect(responseText));
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
                        if (sendHistoryPanel != null) sendHistoryPanel.refresh();
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

            // Collect verbs to scan: the seven standard verbs plus any custom
            // verbs the user has added via the "Custom..." prompt. We read from
            // the dropdown rather than the static VERBS array so a fresh
            // POSTX-style entry gets included automatically. Anything matching
            // the Custom... sentinel is skipped (it's not a real verb).
            final List<String> verbsToScan = new ArrayList<>();
            DefaultComboBoxModel<String> verbModel =
                    (DefaultComboBoxModel<String>) verbCombo.getModel();
            for (int i = 0; i < verbModel.getSize(); i++) {
                String v = verbModel.getElementAt(i);
                if (v == null || CUSTOM_VERB_LABEL.equals(v)) continue;
                verbsToScan.add(v);
            }
            final int totalVerbs = verbsToScan.size();
            if (totalVerbs == 0) return;

            // Build a session stub; workers will fill it as results arrive.
            String originalVerb = (String) verbCombo.getSelectedItem();
            String path = rawText.split("\r?\n")[0].replaceAll("^\\w+\\s", "").replaceAll("\\s.*", "");
            String host = currentService != null ? currentService.host() : "";
            final ScanSession session = new ScanSession(host, path, originalVerb, totalVerbs);

            // Open the live results dialog. Rows will get appended as workers complete.
            final DefaultTableModel model = showScanResultsDialog(session, true);

            final AtomicInteger done = new AtomicInteger(0);
            for (final String verb : verbsToScan) {
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

                        final ScanRecord record = new ScanRecord(verb, statusNum, length, preview, respText);
                        SwingUtilities.invokeLater(() -> {
                            session.records.add(record);
                            model.addRow(new Object[]{record.verb, record.status, "" + record.length, record.preview});
                            int n = done.incrementAndGet();
                            if (n >= totalVerbs) finalizeScan(session);
                        });
                    } catch (Exception ex) {
                        final ScanRecord record = new ScanRecord(verb, "ERR", 0, ex.getMessage(), "Error: " + ex.getMessage());
                        SwingUtilities.invokeLater(() -> {
                            session.records.add(record);
                            model.addRow(new Object[]{record.verb, "ERR", "-", record.preview});
                            int n = done.incrementAndGet();
                            if (n >= totalVerbs) finalizeScan(session);
                        });
                    }
                }, "VerbTamper-Scan-" + verb).start();
            }
        }

        /** Push a completed scan into shared history and refresh the History tab. */
        private void finalizeScan(ScanSession session) {
            scanHistory.add(session);
            if (historyPanel != null) historyPanel.refresh();
        }

        /** True if the response text starts with an HTTP/X 3xx status and has a
         *  Location header. Used to gate the Follow Redirect button.
         *  We accept 301/302/303/307/308 -- any 3xx with a Location.
         */
        private boolean isFollowableRedirect(String responseText) {
            if (responseText == null || responseText.isEmpty()) return false;
            String[] lines = responseText.split("\r?\n");
            if (lines.length == 0) return false;
            // First line: "HTTP/2 302 Found" -> grab the second whitespace-separated token.
            String[] firstParts = lines[0].split("\\s+");
            if (firstParts.length < 2) return false;
            String code = firstParts[1];
            if (code.length() < 3 || code.charAt(0) != '3') return false;
            // Walk headers looking for Location: -- stop at the first blank line.
            for (int i = 1; i < lines.length; i++) {
                String l = lines[i];
                if (l.isEmpty()) break;
                if (l.toLowerCase(java.util.Locale.ROOT).startsWith("location:")) return true;
            }
            return false;
        }

        /** Pull the Location header value out of the response text, or null if absent. */
        private String extractLocation(String responseText) {
            if (responseText == null) return null;
            String[] lines = responseText.split("\r?\n");
            for (int i = 1; i < lines.length; i++) {
                String l = lines[i];
                if (l.isEmpty()) break;
                if (l.toLowerCase(java.util.Locale.ROOT).startsWith("location:")) {
                    return l.substring("Location:".length()).trim();
                }
            }
            return null;
        }

        /**
         * Send a GET to the Location of the current response. Per the user's
         * request, this is single-hop only (no chain following) and uses GET
         * regardless of the original verb. Auth headers from the original
         * request are preserved -- including across cross-origin redirects,
         * because the point of the tool is to see what the redirected
         * endpoint does with your credentials.
         *
         * The new response is appended to the existing response with a
         * separator so the original 3xx stays visible.
         */
        private void doFollowRedirect() {
            if (currentService == null || currentResponse == null) return;
            final String location = extractLocation(currentResponse);
            if (location == null) {
                statusLabel.setText("No Location header to follow");
                return;
            }

            // Resolve the redirect target: either an absolute https://host/path
            // URL (which gives us a new HttpService) or a relative /path that
            // reuses the current host/port/scheme.
            final HttpService targetService;
            final String targetPath;
            if (location.startsWith("http://") || location.startsWith("https://")) {
                try {
                    java.net.URI uri = java.net.URI.create(location);
                    boolean tls = "https".equalsIgnoreCase(uri.getScheme());
                    int port = uri.getPort();
                    if (port == -1) port = tls ? 443 : 80;
                    targetService = HttpService.httpService(uri.getHost(), port, tls);
                    String pathPart = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
                    if (uri.getRawQuery() != null) pathPart = pathPart + "?" + uri.getRawQuery();
                    targetPath = pathPart;
                } catch (Exception ex) {
                    statusLabel.setText("Bad Location URL: " + ex.getMessage());
                    api.logging().logToError("[VerbTamper] Redirect parse failed: " + ex);
                    return;
                }
            } else {
                // Relative path: reuse current service. If it doesn't start with /,
                // resolve against the current request's path -- but in practice
                // most servers send a leading-/ Location.
                targetService = currentService;
                targetPath = location.startsWith("/") ? location : "/" + location;
            }

            // Build a GET request preserving the headers from the textarea but
            // dropping the body and any body-specific headers.
            final String newRequest = buildGetRequestFromCurrent(targetService, targetPath);

            api.logging().logToOutput("[VerbTamper] Following redirect: GET "
                    + targetService.host() + targetPath);

            sendBtn.setEnabled(false);
            followRedirectBtn.setEnabled(false);
            statusLabel.setText("Following redirect to " + targetPath + "...");

            new Thread(() -> {
                try {
                    HttpRequest req = HttpRequest.httpRequest(targetService, newRequest);
                    boolean isHttp2 = newRequest.split("\r?\n")[0].toUpperCase().contains("HTTP/2");
                    HttpMode mode = isHttp2 ? HttpMode.HTTP_2 : HttpMode.AUTO;
                    HttpRequestResponse result = api.http().sendRequest(req, mode);

                    final String responseText;
                    final String statusLine;
                    if (result == null || result.response() == null) {
                        responseText = "(no response received)";
                        statusLine = "no response";
                    } else {
                        String body;
                        try {
                            byte[] bytes = result.response().toByteArray().getBytes();
                            body = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
                        } catch (Exception ex) {
                            body = result.response().toString();
                        }
                        if (body == null || body.isEmpty()) {
                            StringBuilder sb = new StringBuilder();
                            sb.append(result.response().httpVersion()).append(' ')
                              .append(result.response().statusCode()).append(' ')
                              .append(result.response().reasonPhrase()).append("\r\n");
                            result.response().headers().forEach(h ->
                                sb.append(h.name()).append(": ").append(h.value()).append("\r\n"));
                            sb.append("\r\n").append(result.response().bodyToString());
                            body = sb.toString();
                        }
                        responseText = body;
                        statusLine = body.split("\r?\n", 2)[0];
                    }

                    // Append to the current response with a clear separator.
                    final String separator = "\r\n\r\n========== Followed redirect: GET "
                            + targetService.host() + targetPath + " ==========\r\n\r\n";
                    final String combined = currentResponse + separator + responseText;

                    // Log this hop in send history with a [redirect] tag in the
                    // path so it's visible-but-distinct in the history table.
                    final HistoryEntry redirectEntry = new HistoryEntry(
                            newRequest, "GET [redirect]", responseText, targetService);

                    SwingUtilities.invokeLater(() -> {
                        currentResponse = combined;
                        responseArea.setText(combined);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        statusLabel.setText("Followed redirect \u2192 " + statusLine);
                        copyRespBtn.setEnabled(true);
                        // Re-enable in case the new response is itself a redirect.
                        followRedirectBtn.setEnabled(isFollowableRedirect(responseText));
                        history.add(redirectEntry);
                        historyIndex = history.size() - 1;
                        updateNavButtons();
                        if (sendHistoryPanel != null) sendHistoryPanel.refresh();
                    });
                } catch (Exception ex) {
                    api.logging().logToError("[VerbTamper] Redirect send failed: " + ex);
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Redirect send failed: " + ex.getMessage());
                    });
                } finally {
                    SwingUtilities.invokeLater(() -> sendBtn.setEnabled(true));
                }
            }, "VerbTamper-FollowRedirect").start();
        }

        /**
         * Builds a GET request to the given target using the headers currently
         * in the textarea, but rewrites the request line to "GET <path>" and
         * strips the body plus body-specific headers (Content-Type,
         * Content-Length). The Host header is also rewritten if the target
         * host differs from the current request's host.
         */
        private String buildGetRequestFromCurrent(HttpService target, String targetPath) {
            String raw = requestArea.getText();
            String normalised = raw.replace("\r\n", "\n").replace("\r", "\n");
            int blank = normalised.indexOf("\n\n");
            String headerPart = blank == -1 ? normalised : normalised.substring(0, blank);

            // Preserve HTTP version from the original request line.
            String[] lines = headerPart.split("\n", -1);
            String version = "HTTP/2";
            if (lines.length > 0) {
                String[] firstParts = lines[0].split("\\s+");
                if (firstParts.length >= 3) version = firstParts[2];
            }

            StringBuilder out = new StringBuilder();
            out.append("GET ").append(targetPath).append(' ').append(version).append("\r\n");

            // Replay all headers except the request line, Content-Type,
            // Content-Length, and the original Host (we'll write a fresh Host).
            boolean hostWritten = false;
            for (int i = 1; i < lines.length; i++) {
                String l = lines[i];
                if (l.isEmpty()) continue;
                String lower = l.toLowerCase(java.util.Locale.ROOT);
                if (lower.startsWith("content-type:")) continue;
                if (lower.startsWith("content-length:")) continue;
                if (lower.startsWith("host:")) {
                    out.append("Host: ").append(target.host()).append("\r\n");
                    hostWritten = true;
                    continue;
                }
                out.append(l).append("\r\n");
            }
            if (!hostWritten) {
                out.append("Host: ").append(target.host()).append("\r\n");
            }
            out.append("\r\n");  // headers terminator, no body
            return out.toString();
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
            loadHistoryEntry(historyIndex + direction);
        }

        /**
         * Jump to a specific index in the send history. Also used by the
         * Send History tab when the user double-clicks an entry.
         */
        void loadHistoryEntry(int newIndex) {
            if (newIndex < 0 || newIndex >= history.size()) return;
            historyIndex = newIndex;
            HistoryEntry entry = history.get(historyIndex);
            navigating = true;
            selectVerbInCombo(entry.verb);
            requestArea.setForeground(UIManager.getColor("TextArea.foreground"));
            requestArea.setText(entry.requestText);
            requestArea.setCaretPosition(0);
            responseArea.setText(entry.responseText);
            responseArea.setCaretPosition(0);
            currentService = entry.service;
            sendBtn.setEnabled(true);
            scanBtn.setEnabled(true);
            repeaterBtn.setEnabled(true);
            followRedirectBtn.setEnabled(isFollowableRedirect(entry.responseText));
            navigating = false;
            updateNavButtons();
        }

        /** Read-only view of the send history, used by the Send History tab. */
        List<HistoryEntry> sendHistory() {
            return history;
        }

        /**
         * Called by the Send History tab when it has modified the history list
         * (e.g. delete, clear). Resyncs our back/forward state so the counter
         * and buttons don't point at a stale or out-of-bounds index.
         */
        void onSendHistoryExternallyModified() {
            if (history.isEmpty()) {
                historyIndex = -1;
            } else if (historyIndex >= history.size()) {
                historyIndex = history.size() - 1;
            } else if (historyIndex < 0) {
                historyIndex = 0;
            }
            SwingUtilities.invokeLater(this::updateNavButtons);
        }

        private void updateNavButtons() {
            backBtn.setEnabled(historyIndex > 0);
            forwardBtn.setEnabled(historyIndex < history.size() - 1);
            historyLabel.setText((historyIndex + 1) + " / " + history.size());
        }

        private void copyToClipboard(String text) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
        }

        /**
         * Build the absolute URL of the current request from the request line,
         * the Host header, and the HttpService's TLS flag. Returns null if any
         * piece is missing (e.g. the textarea is empty or the placeholder is
         * still showing).
         */
        private String currentRequestUrl() {
            if (currentService == null) return null;
            String raw = requestArea.getText();
            if (raw == null || raw.isEmpty() || raw.startsWith("Right-click")) return null;

            // Path is the second whitespace-separated token on the first line.
            String firstLine = raw.split("\r?\n", 2)[0];
            String[] parts = firstLine.split("\\s+");
            if (parts.length < 2) return null;
            String path = parts[1];

            // Prefer the Host header so user edits are honoured. Fall back to
            // the HttpService's host if the user removed the header.
            String host = currentService.host();
            for (String line : raw.split("\r?\n")) {
                if (line.isEmpty()) break;  // headers terminator
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("host:")) {
                    host = line.substring("host:".length()).trim();
                    break;
                }
            }

            String scheme = currentService.secure() ? "https" : "http";
            int port = currentService.port();
            // Only include the port if it isn't the default for the scheme.
            boolean defaultPort = (scheme.equals("https") && port == 443)
                    || (scheme.equals("http") && port == 80);
            String hostPart = (host.contains(":") || defaultPort) ? host : host + ":" + port;
            return scheme + "://" + hostPart + path;
        }

        /**
         * Resolve the Location header of the current response into an absolute
         * URL. Reuses the redirect-following logic so relative paths get
         * combined with the current host. Returns null if there's no Location.
         */
        private String currentLocationUrl() {
            if (currentResponse == null) return null;
            String location = extractLocation(currentResponse);
            if (location == null) return null;
            if (location.startsWith("http://") || location.startsWith("https://")) {
                return location;
            }
            if (currentService == null) return location;
            String scheme = currentService.secure() ? "https" : "http";
            int port = currentService.port();
            boolean defaultPort = (scheme.equals("https") && port == 443)
                    || (scheme.equals("http") && port == 80);
            String hostPart = defaultPort ? currentService.host() : currentService.host() + ":" + port;
            String pathPart = location.startsWith("/") ? location : "/" + location;
            return scheme + "://" + hostPart + pathPart;
        }

        /**
         * Attach a "Copy URL" right-click menu to a JTextArea. For the response
         * area, also adds a "Copy Location URL" item enabled only when the
         * current response has a Location header. Standard editor actions
         * (Cut/Copy/Paste/Select All) are added below as a separator group so
         * the new menu replaces, rather than competes with, the native one.
         */
        private void attachUrlContextMenu(JTextArea area, boolean isResponse) {
            JPopupMenu menu = new JPopupMenu();

            JMenuItem copyUrlItem = new JMenuItem("Copy URL");
            copyUrlItem.addActionListener(e -> {
                String url = currentRequestUrl();
                if (url != null) {
                    copyToClipboard(url);
                    statusLabel.setText("Copied URL: " + url);
                } else {
                    statusLabel.setText("No URL to copy \u2014 load a request first");
                }
            });
            menu.add(copyUrlItem);

            final JMenuItem copyLocationItem;
            if (isResponse) {
                copyLocationItem = new JMenuItem("Copy Location URL");
                copyLocationItem.addActionListener(e -> {
                    String url = currentLocationUrl();
                    if (url != null) {
                        copyToClipboard(url);
                        statusLabel.setText("Copied Location URL: " + url);
                    } else {
                        statusLabel.setText("No Location header in current response");
                    }
                });
                menu.add(copyLocationItem);
            } else {
                copyLocationItem = null;
            }

            menu.addSeparator();

            JMenuItem cut = new JMenuItem("Cut");
            cut.addActionListener(e -> area.cut());
            JMenuItem copy = new JMenuItem("Copy");
            copy.addActionListener(e -> area.copy());
            JMenuItem paste = new JMenuItem("Paste");
            paste.addActionListener(e -> area.paste());
            JMenuItem selectAll = new JMenuItem("Select All");
            selectAll.addActionListener(e -> area.selectAll());

            // Read-only response area: Cut and Paste don't apply.
            if (!area.isEditable()) {
                menu.add(copy);
                menu.add(selectAll);
            } else {
                menu.add(cut);
                menu.add(copy);
                menu.add(paste);
                menu.add(selectAll);
            }

            // Refresh enabled state when the menu opens, so e.g. "Copy Location
            // URL" is greyed out when there's no Location header.
            menu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
                @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                    copyUrlItem.setEnabled(currentRequestUrl() != null);
                    if (copyLocationItem != null) {
                        copyLocationItem.setEnabled(currentLocationUrl() != null);
                    }
                }
                @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
                @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
            });

            area.setComponentPopupMenu(menu);
        }

        /** Selects the given verb in the dropdown. For standard verbs this is
         *  a simple index match. For non-standard verbs (e.g. PROPFIND from a
         *  loaded request, or POSTX from history replay) we add the verb to
         *  the dropdown right before the "Custom..." sentinel and select it,
         *  so the user can see and use it like any other verb. Caller is
         *  responsible for setting the loading flag if needed. */
        private void selectVerbInCombo(String verb) {
            if (verb == null) return;
            String upper = verb.toUpperCase();
            DefaultComboBoxModel<String> model =
                    (DefaultComboBoxModel<String>) verbCombo.getModel();
            // Already in the dropdown? Just select it.
            int existing = model.getIndexOf(upper);
            if (existing >= 0) {
                verbCombo.setSelectedIndex(existing);
                lastSelectedVerbIndex = existing;
                return;
            }
            // Non-standard verb: add it before the Custom... sentinel and select it.
            int sentinelIdx = model.getIndexOf(CUSTOM_VERB_LABEL);
            if (sentinelIdx >= 0) {
                model.insertElementAt(upper, sentinelIdx);
                verbCombo.setSelectedItem(upper);
            } else {
                model.addElement(upper);
                verbCombo.setSelectedItem(upper);
            }
            lastSelectedVerbIndex = verbCombo.getSelectedIndex();
        }

        private String swapMethod(String raw, String newMethod) {
            int firstSpace = raw.indexOf(' ');
            if (firstSpace == -1) return raw;
            return newMethod + raw.substring(firstSpace);
        }

        /** Builds the initial list of items for the verb dropdown: the seven
         *  standard verbs followed by the "Custom..." sentinel. */
        private String[] buildInitialVerbItems() {
            String[] items = new String[VERBS.length + 1];
            System.arraycopy(VERBS, 0, items, 0, VERBS.length);
            items[VERBS.length] = CUSTOM_VERB_LABEL;
            return items;
        }

        /** Called when the user picks "Custom..." from the verb dropdown.
         *  Prompts for a verb string, validates it lightly (uppercase, trim,
         *  reject empty), and replaces the sentinel item in the dropdown
         *  with the entered verb so it shows up as the selected option.
         *  If the user cancels or enters nothing, reverts to the previous
         *  selection. */
        private void handleCustomVerbPicked() {
            String input = (String) JOptionPane.showInputDialog(
                    this,
                    "Enter a custom HTTP verb (e.g. POSTX, PROPFIND, FOOBAR):",
                    "Custom verb",
                    JOptionPane.PLAIN_MESSAGE,
                    null, null, "");
            if (input == null) {
                // User hit Cancel -- revert to previous selection.
                loading = true;
                verbCombo.setSelectedIndex(lastSelectedVerbIndex);
                loading = false;
                return;
            }
            String verb = input.trim().toUpperCase();
            if (verb.isEmpty()) {
                loading = true;
                verbCombo.setSelectedIndex(lastSelectedVerbIndex);
                loading = false;
                return;
            }

            // Replace the "Custom..." sentinel with the actual entered verb,
            // and add a fresh "Custom..." back at the end so the option is
            // still available for next time.
            loading = true;
            DefaultComboBoxModel<String> model =
                    (DefaultComboBoxModel<String>) verbCombo.getModel();
            // Find and remove any previous custom-verb entries (anything past
            // the standard verbs that isn't the sentinel) so the dropdown
            // doesn't grow unboundedly across many "Custom..." picks.
            for (int i = model.getSize() - 1; i >= VERBS.length; i--) {
                String item = model.getElementAt(i);
                if (!item.equals(CUSTOM_VERB_LABEL)) model.removeElementAt(i);
            }
            // Drop the existing sentinel, append the new verb, then re-append
            // the sentinel so it stays at the bottom.
            int sentinelIdx = model.getIndexOf(CUSTOM_VERB_LABEL);
            if (sentinelIdx >= 0) model.removeElementAt(sentinelIdx);
            model.addElement(verb);
            model.addElement(CUSTOM_VERB_LABEL);
            verbCombo.setSelectedItem(verb);
            lastSelectedVerbIndex = verbCombo.getSelectedIndex();
            loading = false;

            // Apply the new verb to the request line, same as a normal pick.
            String text = requestArea.getText();
            if (!text.isEmpty() && !text.startsWith("Right-click")) {
                String updated = swapMethod(text, verb);
                int caret = requestArea.getCaretPosition();
                requestArea.setText(updated);
                requestArea.setCaretPosition(Math.min(caret, updated.length()));
            }
            statusLabel.setText("Custom verb set to " + verb);
        }

        /**
         * Insert or update a bypass header in the request editor. If a header
         * with the same name already exists, its value is replaced (case-
         * insensitive name match). Otherwise the header is appended at the
         * end of the header block, just before the blank line / body.
         *
         * For method-override entries the verb dropdown is also switched to
         * POST, since the whole point is to smuggle a DELETE/PUT/PATCH intent
         * through a POST-only endpoint.
         */
        private void insertOrReplaceHeader(BypassHeader h) {
            String raw = requestArea.getText();
            if (raw.isEmpty() || raw.startsWith("Right-click")) {
                statusLabel.setText("Load a request first");
                return;
            }

            // Work in normalised \n space; the existing sanitiseHeaders will
            // convert back to CRLF when sending.
            String normalised = raw.replace("\r\n", "\n").replace("\r", "\n");
            int blank = normalised.indexOf("\n\n");
            String headerPart;
            String bodyPart;
            if (blank == -1) {
                headerPart = normalised;
                bodyPart = "";
            } else {
                headerPart = normalised.substring(0, blank);
                bodyPart = normalised.substring(blank);  // keep the \n\n separator
            }

            // Case-insensitive check for existing header.
            String existingPattern = "(?im)^" + java.util.regex.Pattern.quote(h.name) + ":.*$";
            String replacement = h.name + ": " + h.defaultValue;
            String newHeaderPart;
            boolean replaced;
            if (headerPart.matches("(?is).*(^|\\n)" + java.util.regex.Pattern.quote(h.name) + ":.*")) {
                // Header already present: replace its value in-place.
                newHeaderPart = headerPart.replaceAll(existingPattern, replacement);
                replaced = true;
            } else {
                // Insert immediately after the Host: line (conventional placement
                // for most proxies' bypass/override headers). If there's no Host
                // line for some reason, fall back to appending at the end of the
                // header block.
                String hostPattern = "(?im)^(Host:.*)$";
                if (headerPart.matches("(?is).*(^|\\n)Host:.*")) {
                    newHeaderPart = headerPart.replaceFirst(hostPattern, "$1\n" + replacement);
                } else {
                    String trimmed = headerPart;
                    while (trimmed.endsWith("\n")) trimmed = trimmed.substring(0, trimmed.length() - 1);
                    newHeaderPart = trimmed + "\n" + replacement;
                }
                replaced = false;
            }

            // Defensive: when the "body" is empty or whitespace-only (just the
            // CRLF CRLF separator left over from Montoya's toString, with no
            // actual body content after it), drop it so we don't render a
            // visible blank line at the bottom of the editor. sanitiseHeaders
            // will add the correct terminator at send time.
            String combined = newHeaderPart + bodyPart;
            if (bodyPart.trim().isEmpty()) {
                combined = newHeaderPart;
                while (combined.endsWith("\n") || combined.endsWith("\r")) {
                    combined = combined.substring(0, combined.length() - 1);
                }
            }
            requestArea.setText(combined);
            requestArea.setCaretPosition(0);

            // If this is a method-override header, also flip the verb dropdown.
            String extraMsg = "";
            if (h.overrideVerb != null) {
                selectVerbInCombo(h.overrideVerb);
                extraMsg = " (verb set to " + h.overrideVerb + ")";
            }
            statusLabel.setText((replaced ? "Replaced " : "Added ") + h.name + extraMsg);
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
