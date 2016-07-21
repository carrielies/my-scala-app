/*
 * This is a Java library that handles calling CryptoPhoto.
 *   - Main Page
 *       http://cryptophoto.com/
 *   - About CryptoPhoto
 *       http://cryptophoto.com/about
 *   - Register to CryptoPhoto
 *       http://cryptophoto.com/admin/register
 *
 * Copyright (C) 2014 Cryptophoto.com. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package connectors.cryptophoto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;

import static java.lang.System.getProperty;
import static java.net.URLEncoder.encode;

/**
 * Immutable helper class that handles calling the <a href="http://cryptophoto.com/admin/api">CryptoPhoto API</a>.
 *
 * @author <a href="http://cryptophoto.com">CryptoPhoto</a>,
 *         <a href="mailto:tech@cryptophoto.com">tech@cryptophoto.com</a>
 * @version 1.20140728
 */
public class CryptoPhotoUtils {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private final String server;

    private final String publicKey;

    private final byte[] privateKey;

    private final Mac mac; // used to sign outgoing data

    public CryptoPhotoUtils(String publicKey, String privateKey) throws InvalidKeyException {
        this(null, publicKey, privateKey);
    }

    public CryptoPhotoUtils(String server, String publicKey, String privateKey) throws InvalidKeyException {
        if (publicKey == null || privateKey == null) {
            throw new NullPointerException("cannot use null public or private CryptoPhoto keys");
        }

        this.server = server == null || (server = server.trim()).length() == 0 ? "http://cryptophoto.com" : server;
        this.publicKey = publicKey;
        this.privateKey = privateKey.getBytes();

        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(this.privateKey, "HmacSHA1"));
        } catch (NoSuchAlgorithmException e) {
            // cannot happen since we hard-code the algorithm
        }
        this.mac = mac;
    }

    public static String getVisibleIp() {
        String ip = getProperty("ip");
        if (ip == null || ip.trim().length() == 0) {
            InputStream in = null;
            try {
                HttpURLConnection connection = (HttpURLConnection) new URL("https://cp.vu/show_my_ip").openConnection();
                ip = new BufferedReader(new InputStreamReader(in = connection.getInputStream())).readLine();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return ip;
    }

    public CryptoPhotoResponse getSession(String userId, String ip)
        throws IOException, CryptoPhotoResponseParseException {
        long time = new Date().getTime() / 1000L; // number of seconds since epoch...

        String signature =
            sign(new StringBuilder(new String(privateKey)).append(time).append(userId).append(publicKey).toString());

        String data = new StringBuilder("publickey=").append(encode(publicKey, "UTF-8")).append("&uid=")
                                                     .append(encode(userId, "UTF-8")).append("&time=").append(time)
                                                     .append("&signature=").append(encode(signature, "UTF-8"))
                                                     .append("&ip=").append(encode(ip, "UTF-8")).toString();

        URL url = new URL(server + "/api/get/session");

        return parseSession(post(url, data.getBytes()));
    }

    protected String sign(String data) {
        if (data == null) {
            return null;
        }

        byte[] bytes = mac.doFinal(data.getBytes());
        char[] chars = new char[bytes.length * 2];

        for (int i = 0; i < bytes.length; i++) { // this 'to-hex' transformation should be quite fast...
            int v = bytes[i] & 0xFF;
            chars[i * 2] = HEX[v >>> 4];
            chars[i * 2 + 1] = HEX[v & 0x0F];
        }

        return new String(chars);
    }

    protected CryptoPhotoResponse parseSession(String cpResponse) throws CryptoPhotoResponseParseException {
        if (cpResponse == null) {
            throw new NullPointerException("cannot parse a null CryptoPhoto response");
        }

        String[] lines = cpResponse.split("(\\r?\\n)+");
        if (lines.length < 2) {
            throw new CryptoPhotoResponseParseException("unexpected CryptoPhoto response length: less than 2 lines");
        }

        CryptoPhotoResponse response = new CryptoPhotoResponse();

        String status = lines[0].trim().toLowerCase();
        switch (status) { // requires Java 7; if not available, just use if/else-if/else with .equals()
        case "success":
            response.put("id", lines[1].trim());
            response.put("valid", "true");
            break;
        case "error":
            response.put("error", lines[1].trim());
            response.put("valid", "false");
            break;
        default:
            throw new CryptoPhotoResponseParseException("unexpected CryptoPhoto response status: " + status);
        }

        if (lines.length > 2) {
            response.put("token", lines[2].trim());
        }
        if (lines.length > 3) {
            response.put("signature", lines[3].trim());
        }

        return response;
    }

    protected String post(URL url, byte[] data) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Length", String.valueOf(data.length));
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        OutputStream out = connection.getOutputStream();
        try {
            out.write(data);
            out.flush();
        } finally {
            out.close();
        }

        StringBuilder response = new StringBuilder();

        InputStream in = connection.getInputStream();
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                response.append(line).append("\n");
            }
        } finally {
            in.close();
        }

        return response.toString();
    }

    public String getTokenGenerationWidget(CryptoPhotoResponse cryptoPhotoSession) throws CryptoPhotoInvalidSession {
        if (cryptoPhotoSession == null) {
            throw new NullPointerException("cannot obtain a token generation widget using a null CryptoPhoto session");
        }

        if (!cryptoPhotoSession.is("valid")) {
            throw new CryptoPhotoInvalidSession(cryptoPhotoSession);
        }

        return "<script type=\"text/javascript\" src=\"" + server + "/api/token?sd=" + cryptoPhotoSession.get("id") +
               "\"></script>";
    }

    public String getChallengeWidget(CryptoPhotoResponse cryptoPhotoSession) throws CryptoPhotoInvalidSession {
        if (cryptoPhotoSession == null) {
            throw new NullPointerException("cannot obtain a challenge widget using a null CryptoPhoto session");
        }

        if (!cryptoPhotoSession.is("valid")) {
            throw new CryptoPhotoInvalidSession(cryptoPhotoSession);
        }

        return "<script type=\"text/javascript\" src=\"" + server + "/api/challenge?sd=" +
               cryptoPhotoSession.get("id") + "\"></script>";
    }

    public CryptoPhotoResponse verify(String selector, String responseRow, String responseCol, String cph,
                                      String userId, String ip) throws IOException, CryptoPhotoResponseParseException {
        long time = new Date().getTime() / 1000L; // number of seconds since epoch...

        String signature =
            sign(new StringBuilder(new String(privateKey)).append(time).append(userId).append(publicKey).toString());

        String data = new StringBuilder("publickey=").append(encode(publicKey, "UTF-8")).append("&uid=")
                                                     .append(encode(userId, "UTF-8")).append("&time=").append(time)
                                                     .append("&signature=").append(encode(signature, "UTF-8"))
                                                     .append("&response_row=").append(encode(responseRow, "UTF-8"))
                                                     .append("&response_col=").append(encode(responseCol, "UTF-8"))
                                                     .append("&selector=").append(encode(selector, "UTF-8"))
                                                     .append("&cph=").append(encode(cph, "UTF-8")).append("&ip=")
                                                     .append(encode(ip, "UTF-8")).toString();

        URL url = new URL(server + "/api/verify");

        return parseVerification(post(url, data.getBytes()));
    }

    protected CryptoPhotoResponse parseVerification(String cpResponse) throws CryptoPhotoResponseParseException {
        if (cpResponse == null) {
            throw new NullPointerException("cannot parse a null CryptoPhoto response");
        }

        String[] lines = cpResponse.split("(\\r?\\n)+");
        if (lines.length < 1) {
            throw new CryptoPhotoResponseParseException("unexpected CryptoPhoto response length: less than 1 line");
        }

        CryptoPhotoResponse response = new CryptoPhotoResponse();

        String status = lines[0].trim().toLowerCase();
        switch (status) { // requires Java 7; if not available, just use if/else-if/else with .equals()
        case "success":
            response.put("valid", "true");
            if (lines.length > 1) {
                response.put("message", lines[1].trim());
            }
            break;
        case "error":
            response.put("valid", "false");
            if (lines.length > 1) {
                response.put("error", lines[1].trim());
            }
            break;
        default:
            throw new CryptoPhotoResponseParseException("unexpected CryptoPhoto response status: " + status);
        }

        if (lines.length > 2) {
            response.put("signature", lines[2].trim());
        }

        return response;
    }

    /**
     * CryptoPhoto API response.
     *
     * @author <a href="http://cryptophoto.com">CryptoPhoto</a>,
     *         <a href="mailto:tech@cryptophoto.com">tech@cryptophoto.com</a>
     * @version 1.20140728
     */
    public static class CryptoPhotoResponse extends HashMap<String, String> {

        /**
         * Equivalent to calling <code>is(key)</code>. For some keys, 'has' sounds better (e.g. has("token")).
         */
        public boolean has(String key) { return is(key); }

        /**
         * @return <code>true</code> if the value to which the specified <code>key</code> is mapped is
         * non-<code>null</code> and equals (case-insensitively) 'true', 'yes' or '1'.
         */
        public boolean is(String key) {
            String value = get(key);
            return value != null &&
                   ((value = value.toLowerCase()).equals("true") || value.equals("yes") || value.equals("1"));
        }
    }
}
