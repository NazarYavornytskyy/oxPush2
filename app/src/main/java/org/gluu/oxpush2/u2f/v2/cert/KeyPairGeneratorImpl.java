/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.cert;

import android.util.Log;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.gluu.oxpush2.u2f.v2.exception.U2FException;
import org.gluu.oxpush2.util.Utils;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

/**
 * Service to work generate key pair  and other crypto methods
 *
 * Created by Yuriy Movchan on 12/07/2015.
 */
public class KeyPairGeneratorImpl implements org.gluu.oxpush2.u2f.v2.cert.KeyPairGenerator {

    private static final boolean DEBUG = true;
    private static final String TAG = KeyPairGeneratorImpl.class.getName();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public KeyPair generateKeyPair() {
        // generate ECC key
        SecureRandom random = new SecureRandom();

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
            g.initialize(ecSpec, random);
            KeyPair keyPair = g.generateKeyPair();

            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public byte[] sign(byte[] signedData, PrivateKey privateKey) throws U2FException {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(signedData);
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new U2FException("Error when signing", e);
        } catch (SignatureException e) {
            throw new U2FException("Error when signing", e);
        } catch (InvalidKeyException e) {
            throw new U2FException("Error when signing", e);
        }
    }

    @Override
    public byte[] generateKeyHandle(byte[] applicationSha256) {
        SecureRandom random = new SecureRandom();
        byte[] keyHandle = new byte[64];
        random.nextBytes(keyHandle);
        return keyHandle;
    }

    @Override
    public byte[] encodePublicKey(PublicKey publicKey) {
        byte[] encodedWithPadding = publicKey.getEncoded();
        byte[] encoded = new byte[65];
        System.arraycopy(encodedWithPadding, 26, encoded, 0, encoded.length);

        if (DEBUG) {
            Log.d(TAG, "Encoded public key: " + Utils.encodeHexString(encoded));
        }

        return encoded;
    }

    public String keyPairToJson(KeyPair keyPair) {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        BigInteger x = publicKey.getQ().getAffineXCoord().toBigInteger();
        BigInteger y = publicKey.getQ().getAffineYCoord().toBigInteger();
        BigInteger d = privateKey.getD();

        try {
            JSONObject jsonPrivateKey = new JSONObject();
            jsonPrivateKey.put("d", Utils.encodeHexString(d.toByteArray()));

            JSONObject jsonPublicKey = new JSONObject();
            jsonPublicKey.put("x", Utils.encodeHexString(x.toByteArray()));
            jsonPublicKey.put("y", Utils.encodeHexString(y.toByteArray()));

            JSONObject jsonKeyPair = new JSONObject();
            jsonKeyPair.put("privateKey", jsonPrivateKey);
            jsonKeyPair.put("publicKey", jsonPublicKey);

            String keyPairJson = jsonKeyPair.toString();

            if (DEBUG) {
                Log.d(TAG, "JSON key pair: " + keyPairJson);
            }

            return keyPairJson;
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return null;
    }

    public KeyPair keyPairFromJson(String keyPairJson) {
        BigInteger x = null;
        BigInteger y = null;
        BigInteger d = null;

        try {
            JSONObject jsonKeyPair = (JSONObject) new JSONTokener(keyPairJson).nextValue();

            JSONObject jsonPrivateKey = jsonKeyPair.getJSONObject("privateKey");
            d = new BigInteger(Utils.decodeHexString(jsonPrivateKey.getString("d")));

            JSONObject jsonPublicKey = jsonKeyPair.getJSONObject("publicKey");
            x = new BigInteger(Utils.decodeHexString(jsonPublicKey.getString("x")));
            y = new BigInteger(Utils.decodeHexString(jsonPublicKey.getString("y")));
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (DecoderException e) {
            e.printStackTrace();
        }

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        ECCurve curve = ecSpec.getCurve();
        ECPoint validatePoint = curve.validatePoint(x, y);

        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(validatePoint, ecSpec);
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecSpec);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String keyHandleToKey(byte[] keyHandle) {
        return Utils.encodeHexString(keyHandle);
    }

}
