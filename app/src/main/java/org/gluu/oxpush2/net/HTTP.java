/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

/**
 * Network communication service
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
package org.gluu.oxpush2.net;

import android.util.Log;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Methods to send requests to oxAuth server
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class HTTP {

    public static String get(String baseUrl, Map<String, String> params) throws IOException {
        Log.d("oxpush2-http", "Attempting to send: " + params);
        initTrustAllTrustManager();

        HttpURLConnection connection = null;

        try {
            String urlParameters = getEncodedUrlParameters(params);
            URL url;
            if (urlParameters == null) {
                url = new URL(baseUrl);
            } else {
                url = new URL(baseUrl + '?' + urlParameters);
            }

            connection = (HttpURLConnection) url.openConnection();
            connection.setUseCaches(false);

            //Get Response
            InputStream is = connection.getInputStream();

            return readStream(is);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public static String post(String baseUrl, Map<String, String> params) throws IOException {
        initTrustAllTrustManager();

        HttpURLConnection connection = null;

        try {
            String urlParameters = getEncodedUrlParameters(params);

            URL url = new URL(baseUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));

            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);

            //Send request
            DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
            wr.writeBytes(urlParameters);
            wr.flush();
            wr.close();

            // Read Response
            InputStream is = connection.getInputStream();
            return readStream(is);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String getEncodedUrlParameters(Map<String, String> params) throws UnsupportedEncodingException {
        if (params == null) {
            return null;
        }

        StringBuilder urlParametersBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            Log.d("HTTP", key + " = " + value);
            if (value == null) {
                Log.w("HTTP", "Key '" + key + "' value is null");
                continue;
            }

            urlParametersBuilder.append("&").append(entry.getKey()).append("=").append(URLEncoder.encode(entry.getValue(), "UTF-8"));
        }
        urlParametersBuilder.deleteCharAt(0);

        return urlParametersBuilder.toString();
    }

    private static String readStream(InputStream is) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));

        String line;
        StringBuilder result = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }

        reader.close();

        return result.toString();
    }

    private static void initTrustAllTrustManager() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception ex) {
            Log.d("", "Failed to install trust all TrustManager", ex);
        }

        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

            @Override
            public boolean verify(String s, SSLSession sslSession) {
                return true;
            }

        });
    }

}

/*
byte[] der = loadPemCertificate(
        new ByteArrayInputStream(certificateString.getBytes()));
ByteArrayInputStream derInputStream = new ByteArrayInputStream(der);
CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
X509Certificate cert = (X509Certificate) certificateFactory
        .generateCertificate(derInputStream);
String alias = cert.getSubjectX500Principal().getName();

KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
trustStore.load(null);
        trustStore.setCertificateEntry(alias, cert);

        Now that we have the “trustStore” KeyStore with the server’s certificate, we use it to initialize the SSLContext. Adding to the code that we had before, production of the SSLContext now becomes:

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
        kmf.init(keyStore, clientCertPassword.toCharArray());
        KeyManager[] keyManagers = kmf.getKeyManagers();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(trustStore);
        TrustManager[] trustManagers = tmf.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers, trustManagers, null);
*/