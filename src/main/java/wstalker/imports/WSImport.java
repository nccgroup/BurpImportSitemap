/*
 * Released as open source by NCC Group Plc - http://www.nccgroup.com/
 *
 * Developed by
 * - Jose Selvi, jose dot selvi at nccgroup dot com
 * - Stefan Kunz, https://github.com/kunzstef
 *
 * https://github.com/nccgroup/BurpImportSitemap
 *
 * Released under AGPL see LICENSE for more information
 */

package wstalker.imports;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import javax.swing.JFileChooser;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.Har;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarHeader;
import de.sstoehr.harreader.model.HarRequest;
import de.sstoehr.harreader.model.HarResponse;
import wstalker.WStalker;

public class WSImport {

    public static String getLoadFile() {
        JFileChooser chooser = null;
        chooser = new JFileChooser();
        chooser.setDialogTitle("Import File");
        int val = chooser.showOpenDialog(null);

        if (val == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile().getAbsolutePath();
        }

        return "";
    }

    public static ArrayList<String> readFile(String filename) {
        BufferedReader reader;
        ArrayList<String> lines = new ArrayList<>();

        try {
            reader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException e) {
            return new ArrayList<>();
        }
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            return new ArrayList<>();
        }

        return lines;
    }

    public static ArrayList<IHttpRequestResponse> importWStalker() {
        ArrayList<String> lines = new ArrayList<>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<>();
        IExtensionHelpers helpers = WStalker.callbacks.getHelpers();

        String filename = getLoadFile();
        if (filename.length() == 0) { // exit if no file selected
            return new ArrayList<>();
        }

        lines = readFile(filename);
        Iterator<String> i = lines.iterator();

        while (i.hasNext()) {
            try {
                String line = i.next();
                String[] v = line.split(","); // Format: "base64(request),base64(response),url"

                byte[] request = helpers.base64Decode(v[0]);
                byte[] response = helpers.base64Decode(v[1]);
                String url = v[3];

                WSRequestResponse x = new WSRequestResponse(url, request, response);
                requests.add(x);

            } catch (Exception e) {
                return new ArrayList<>();
            }
        }

        return requests;
    }

    private static ArrayList<IHttpRequestResponse> parseHAR(String filename)
            throws HarReaderException, MalformedURLException {
        HarReader harReader = new HarReader();
        Har har = harReader.readFromFile(new File(filename));
        ArrayList<IHttpRequestResponse> requests = new ArrayList<>();

        for (HarEntry entry : har.getLog().getEntries()) {
            HarRequest request = entry.getRequest();

            URL url = new URL(request.getUrl());

            StringBuilder requestString = new StringBuilder();
            requestString.append(request.getMethod()).append(" ").append(url.getFile()).append(" ")
                    .append(request.getHttpVersion()).append("\n");

            for (HarHeader header : request.getHeaders())
                requestString.append(header.getName()).append(": ").append(header.getValue()).append("\n");

            requestString.append("\n");

            if (request.getPostData().getText() != null)
                requestString.append(request.getPostData().getText());

            HarResponse response = entry.getResponse();
            StringBuilder responseString = new StringBuilder();
            responseString.append(response.getHttpVersion()).append(" ").append(response.getStatus()).append(" ")
                    .append(response.getStatusText()).append("\n");

            for (HarHeader header : response.getHeaders())
                responseString.append(header.getName()).append(": ").append(header.getValue()).append("\n");

            if (response.getContent() == null) {
                responseString.append("\n");
            } else {
                responseString.append("Content-Length: ").append(response.getContent().getSize()).append("\n\n")
                        .append(response.getContent().getText());
            }

            WSRequestResponse x = new WSRequestResponse(url.toString(), requestString.toString().getBytes(),
                    responseString.toString().getBytes());
            requests.add(x);
        }

        return requests;
    }

    public static ArrayList<IHttpRequestResponse> importHAR() {
        ArrayList<String> lines = new ArrayList<>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<>();
        IExtensionHelpers helpers = WStalker.callbacks.getHelpers();

        String filename = getLoadFile();
        if (filename.length() != 0) { // exit if no file selected
            try {
                requests = parseHAR(filename);
            } catch (MalformedURLException | HarReaderException e) {}
        }

        return requests;
    }

    public static ArrayList<IHttpRequestResponse> importZAP() {
        ArrayList<String> lines = new ArrayList<>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<>();
        IExtensionHelpers helpers = WStalker.callbacks.getHelpers();

        String filename = getLoadFile();
        if (filename.length() == 0) { // exit if no file selected
            return new ArrayList<>();
        }

        lines = readFile(filename);
        Iterator<String> i = lines.iterator();

        // Format:
        // ===[0-9]+ ==========
        // REQUEST
        // <empty>
        // RESPONSE
        String reSeparator = "^=+ ?[0-9]+ ?=+$";
        String reResponse = "^HTTP/[0-9]\\.[0-9] [0-9]+ .*$";

        // Ignore first line, since it should be a separator
        if (i.hasNext()) {
            i.next();
        }

        boolean isRequest = true;
        String requestBuffer = "";
        String responseBuffer = "";
        String url = "";

        // Loop lines
        while (i.hasNext()) {
            String line = i.next();

            // Request and Response Ready
            if (line.matches(reSeparator) || !i.hasNext()) {
                // TODO: Remove one or two \n at the end of requestBuffer

                byte[] req = helpers.stringToBytes(requestBuffer);
                byte[] res = helpers.stringToBytes(responseBuffer);

                // Add IHttpRequestResponse Object
                WSRequestResponse x = new WSRequestResponse(url, req, res);
                requests.add(x);

                // Reset content
                isRequest = true;
                requestBuffer = "";
                responseBuffer = "";
                url = "";

                continue;
            }

            // It's the beginning of a request
            if (requestBuffer.length() == 0) {
                try {
                    // Expected format: "GET https://whatever/whatever.html HTTP/1.1"
                    String[] x = line.split(" ");
                    url = x[1];

                    URL u = new URL(url);
                    String path = u.getPath();
                    line = x[0] + " " + path + " " + x[2]; // fix the path in the request

                } catch (Exception e) {
                    return new ArrayList<>();
                }
            }

            // It's the beginning of a response
            if (line.matches(reResponse)) {
                isRequest = false;
            }

            // Add line to the corresponding buffer
            if (isRequest) {
                requestBuffer += line;
                requestBuffer += "\n";
            } else {
                responseBuffer += line;
                responseBuffer += "\n";
            }
        }

        return requests;
    }

    public static boolean loadImported(ArrayList<IHttpRequestResponse> requests) {

        return true;
    }
}
