/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.gluu.oxpush2.store.AndroidKeyDataStore;
import org.gluu.oxpush2.u2f.v2.cert.KeyPairGeneratorImpl;
import org.gluu.oxpush2.u2f.v2.codec.RawMessageCodec;
import org.gluu.oxpush2.u2f.v2.codec.RawMessageCodecImpl;
import org.gluu.oxpush2.u2f.v2.device.U2FKeyImpl;
import org.gluu.oxpush2.u2f.v2.exception.U2FException;
import org.gluu.oxpush2.u2f.v2.model.AuthenticateRequest;
import org.gluu.oxpush2.u2f.v2.model.AuthenticateResponse;
import org.gluu.oxpush2.u2f.v2.model.EnrollmentRequest;
import org.gluu.oxpush2.u2f.v2.model.EnrollmentResponse;
import org.gluu.oxpush2.u2f.v2.model.TokenResponse;
import org.gluu.oxpush2.u2f.v2.store.DataStore;
import org.gluu.oxpush2.u2f.v2.user.UserPresenceVerifierImpl;
import org.gluu.oxpush2.util.Utils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/**
 * Service to process authentication/enrollment Fido U2F requests
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class U2F_V2 {

    protected static final PrivateKey VENDOR_CERTIFICATE_PRIVATE_KEY = parsePrivateKey(
            "f3fccc0d00d8031954f90864d43c247f4bf5f0665c6b50cc17749a27d1cf7664");
    // Constants for ClientData.typ
    private static final String REQUEST_TYPE_REGISTER = "navigator.id.finishEnrollment";
    private static final String REQUEST_TYPE_AUTHENTICATE = "navigator.id.getAssertion";
    // Constants for building ClientData.challenge
    private static final String JSON_PROPERTY_REQUEST_TYPE = "typ";
    private static final String JSON_PROPERTY_SERVER_CHALLENGE_BASE64 = "challenge";
    private static final String JSON_PROPERTY_SERVER_ORIGIN = "origin";
    private static final String VENDOR_CERTIFICATE_HEX =
            "3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce"
                    + "3d0403023017311530130603550403130c476e756262792050696c6f74301e17"
                    + "0d3132303831343138323933325a170d3133303831343138323933325a303131"
                    + "2f302d0603550403132650696c6f74476e756262792d302e342e312d34373930"
                    + "313238303030313135353935373335323059301306072a8648ce3d020106082a"
                    + "8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c144668"
                    + "2c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf02"
                    + "03b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cd"
                    + "b6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220"
                    + "631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df";
    protected static final X509Certificate VENDOR_CERTIFICATE =
            parseCertificate(VENDOR_CERTIFICATE_HEX);

    private static final boolean DEBUG = true;
    private static final String TAG = U2F_V2.class.getName();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private U2FKeyImpl u2fKey;
    private RawMessageCodec rawMessageCodec;

    public U2F_V2(DataStore dataStore) {
        this.rawMessageCodec = new RawMessageCodecImpl();

        this.u2fKey = new U2FKeyImpl(
                VENDOR_CERTIFICATE,
                VENDOR_CERTIFICATE_PRIVATE_KEY,
                new KeyPairGeneratorImpl(),
                this.rawMessageCodec,
                dataStore,
                new UserPresenceVerifierImpl());

    }

    public static X509Certificate parseCertificate(String encodedDerCertificateHex) {
        return parseCertificate(parseHex(encodedDerCertificateHex));
    }

    public static X509Certificate parseCertificate(byte[] encodedDerCertificate) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    new ByteArrayInputStream(encodedDerCertificate));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey parsePrivateKey(String keyBytesHex) {
        try {
            KeyFactory fac = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(
                    new BigInteger(keyBytesHex, 16),
                    ecSpec);
            return fac.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
//        } catch (NoSuchProviderException e) {
//            throw new RuntimeException(e);
        }
    }

    public static byte[] parseHex(String hexEncoded) {
        try {
            return Hex.decodeHex(hexEncoded.toCharArray());
        } catch (DecoderException ex) {
            throw new RuntimeException(ex);
        }
    }

    public TokenResponse enroll(String jsonRequest, String origin) throws JSONException, IOException, U2FException {
        JSONObject request = (JSONObject) new JSONTokener(jsonRequest).nextValue();

        if (request.has("registerRequests")) {
            JSONArray registerRequestArray = request.getJSONArray("registerRequests");
            if (registerRequestArray.length() == 0) {
                throw new RuntimeException("Failed to get registration request!");
            }
            request = (JSONObject) registerRequestArray.get(0);
        }

        if (!request.getString("version").equals("U2F_V2")) {
            throw new RuntimeException("Unsupported U2F_V2 version!");
        }

        String version = request.getString("version");
        String appParam = request.getString("appId");
        String challenge = request.getString(JSON_PROPERTY_SERVER_CHALLENGE_BASE64);

        EnrollmentResponse enrollmentResponse = u2fKey.register(new EnrollmentRequest(version, appParam, challenge, origin));

        byte[] resp = rawMessageCodec.encodeRegisterResponse(enrollmentResponse);

        JSONObject clientData = new JSONObject();
        clientData.put(JSON_PROPERTY_REQUEST_TYPE, REQUEST_TYPE_REGISTER);
        clientData.put(JSON_PROPERTY_SERVER_CHALLENGE_BASE64, challenge);
        clientData.put(JSON_PROPERTY_SERVER_ORIGIN, origin);

        String clientDataString = clientData.toString();

        JSONObject response = new JSONObject();
        response.put("registrationData", Utils.base64UrlEncode(resp));
        response.put("clientData", Utils.base64UrlEncode(clientDataString.getBytes(Charset.forName("ASCII"))));

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setResponse(response.toString());
        tokenResponse.setChallenge(new String(challenge));
        tokenResponse.setKeyHandle(new String(enrollmentResponse.getKeyHandle()));

        return tokenResponse;
    }

    public TokenResponse sign(String jsonRequest, String origin) throws JSONException, IOException, U2FException {
        if (DEBUG) {
            Log.d(TAG, "Starting to process sign request: " + jsonRequest);
        }
        JSONObject request = (JSONObject) new JSONTokener(jsonRequest).nextValue();

        JSONArray authenticateRequestArray = null;
        if (request.has("authenticateRequests")) {
            authenticateRequestArray = request.getJSONArray("authenticateRequests");
            if (authenticateRequestArray.length() == 0) {
                throw new RuntimeException("Failed to get authentication request!");
            }
        } else {
            authenticateRequestArray = new JSONArray();
            authenticateRequestArray.put(request);
        }

        Log.i(TAG, "Found " + authenticateRequestArray.length() + " authentication requests");

        AuthenticateResponse authenticateResponse = null;
        String authenticatedChallenge = null;
        JSONObject authRequest = null;
        for (int i = 0; i < authenticateRequestArray.length(); i++) {
            if (DEBUG) {
                Log.d(TAG, "Process authentication request: " + authRequest);
            }
            authRequest = (JSONObject) authenticateRequestArray.get(i);

            if (!authRequest.getString("version").equals("U2F_V2")) {
                throw new RuntimeException("Unsupported U2F_V2 version!");
            }

            String version = authRequest.getString("version");
            String appParam = authRequest.getString("appId");
            String challenge = authRequest.getString(JSON_PROPERTY_SERVER_CHALLENGE_BASE64);
            byte[] keyHandle = Base64.decode(authRequest.getString("keyHandle"), Base64.URL_SAFE | Base64.NO_WRAP);

            authenticatedChallenge = authRequest.getString(JSON_PROPERTY_SERVER_CHALLENGE_BASE64);
            authenticateResponse = u2fKey.authenticate(new AuthenticateRequest(version, AuthenticateRequest.USER_PRESENCE_SIGN , challenge, appParam, keyHandle));
            if (DEBUG) {
                Log.d(TAG, "Authentication response: " + authenticateResponse);
            }
            if (authenticateResponse != null) {
                break;
            }
        }

        if (authenticateResponse == null) {
            return null;
        }

        byte[] resp = rawMessageCodec.encodeAuthenticateResponse(authenticateResponse);

        JSONObject clientData = new JSONObject();
        clientData.put(JSON_PROPERTY_REQUEST_TYPE, REQUEST_TYPE_AUTHENTICATE);
        clientData.put(JSON_PROPERTY_SERVER_CHALLENGE_BASE64, authRequest.getString(JSON_PROPERTY_SERVER_CHALLENGE_BASE64));
        clientData.put(JSON_PROPERTY_SERVER_ORIGIN, origin);
        String clientDataString = clientData.toString();

        JSONObject response = new JSONObject();
        response.put("signatureData", Utils.base64UrlEncode(resp));
        response.put("clientData", Utils.base64UrlEncode(clientDataString.getBytes(Charset.forName("ASCII"))));
        response.put("keyHandle", authRequest.getString("keyHandle"));

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setResponse(response.toString());
        tokenResponse.setChallenge(authenticatedChallenge);
        tokenResponse.setKeyHandle(new String(authRequest.getString("keyHandle")));

        return tokenResponse;
    }

}
