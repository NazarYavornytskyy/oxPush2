/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.device;

import org.gluu.oxpush2.u2f.v2.codec.RawMessageCodec;
import org.gluu.oxpush2.u2f.v2.exception.U2FException;
import org.gluu.oxpush2.u2f.v2.cert.KeyPairGenerator;
import org.gluu.oxpush2.u2f.v2.codec.RawMessageCodecImpl;
import org.gluu.oxpush2.u2f.v2.model.AuthenticateRequest;
import org.gluu.oxpush2.u2f.v2.model.AuthenticateResponse;
import org.gluu.oxpush2.u2f.v2.model.EnrollmentRequest;
import org.gluu.oxpush2.u2f.v2.model.EnrollmentResponse;
import org.gluu.oxpush2.u2f.v2.store.DataStore;
import org.gluu.oxpush2.u2f.v2.user.UserPresenceVerifier;
import org.gluu.oxpush2.util.Utils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * Fido U2F key service to process enrollment/authentication request
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class U2FKeyImpl implements U2FKey {

    private static final Logger Log = Logger.getLogger(U2FKeyImpl.class.getName());

    private final X509Certificate vendorCertificate;
    private final PrivateKey certificatePrivateKey;
    private final KeyPairGenerator keyPairGenerator;
    private final RawMessageCodec rawMessageCodec;
    private final DataStore dataStore;
    private final UserPresenceVerifier userPresenceVerifier;

    public U2FKeyImpl(X509Certificate vendorCertificate, PrivateKey certificatePrivateKey,
                      KeyPairGenerator keyPairGenerator, RawMessageCodec rawMessageCodec,
                      DataStore dataStore, UserPresenceVerifier userPresenceVerifier) {
        this.vendorCertificate = vendorCertificate;
        this.certificatePrivateKey = certificatePrivateKey;
        this.keyPairGenerator = keyPairGenerator;
        this.rawMessageCodec = rawMessageCodec;
        this.dataStore = dataStore;
        this.userPresenceVerifier = userPresenceVerifier;
    }

    @Override
    public EnrollmentResponse register(EnrollmentRequest enrollmentRequest) throws U2FException {
        Log.info(">> register");

        byte[] applicationSha256 = enrollmentRequest.getApplicationSha256();
        byte[] challengeSha256 = enrollmentRequest.getChallengeSha256();

        Log.info(" -- Inputs --");
        Log.info("  applicationSha256: " + Utils.encodeHexString(applicationSha256));
        Log.info("  challengeSha256: " + Utils.encodeHexString(challengeSha256));

        byte userPresent = userPresenceVerifier.verifyUserPresence();
        if ((userPresent & UserPresenceVerifier.USER_PRESENT_FLAG) == 0) {
            throw new U2FException("Cannot verify user presence");
        }

        KeyPair keyPair = keyPairGenerator.generateKeyPair(applicationSha256, challengeSha256);
        byte[] keyHandle = keyPairGenerator.generateKeyHandle(applicationSha256);

        dataStore.storeKeyPair(keyPairGenerator.keyHandleToKey(keyHandle), keyPairGenerator.keyPairToJson(keyPair));

        byte[] userPublicKey = keyPairGenerator.encodePublicKey(keyPair.getPublic());

        byte[] signedData = rawMessageCodec.encodeRegistrationSignedBytes(applicationSha256, challengeSha256,
                keyHandle, userPublicKey);
        Log.info("Signing bytes " + Utils.encodeHexString(signedData));

        byte[] signature = keyPairGenerator.sign(signedData, certificatePrivateKey);

        Log.info(" -- Outputs --");
        Log.info("  userPublicKey: " + Utils.encodeHexString(userPublicKey));
        Log.info("  keyHandle: " + Utils.encodeHexString(keyHandle));
        Log.info("  vendorCertificate: " + vendorCertificate);
        Log.info("  signature: " + Utils.encodeHexString(signature));

        Log.info("<< register");

        return new EnrollmentResponse(userPublicKey, keyHandle, vendorCertificate, signature);
    }

    @Override
    public AuthenticateResponse authenticate(AuthenticateRequest authenticateRequest)
            throws U2FException {
        Log.info(">> authenticate");
        byte[] keyHandle = authenticateRequest.getKeyHandle();

        String keyHandleKey = keyPairGenerator.keyHandleToKey(keyHandle);

        String keyPairJson = dataStore.getKeyPair(keyHandleKey);
        if (keyPairJson == null) {
            Log.warning("  There is no keyPair for keyHandle: " + Utils.encodeHexString(keyHandle));
            return null;
        }

        KeyPair keyPair = keyPairGenerator.keyPairFromJson(keyPairJson);
        if (keyPair == null) {
            Log.warning("  There is no keyPair for keyHandle: " + Utils.encodeHexString(keyHandle));
            return null;
        }

        byte control = authenticateRequest.getControl();
        byte[] applicationSha256 = authenticateRequest.getApplicationSha256();
        byte[] challengeSha256 = authenticateRequest.getChallengeSha256();

        Log.info(" -- Inputs --");
        Log.info("  control: " + control);
        Log.info("  applicationSha256: " + Utils.encodeHexString(applicationSha256));
        Log.info("  challengeSha256: " + Utils.encodeHexString(challengeSha256));
        Log.info("  keyHandle: " + Utils.encodeHexString(keyHandle));

        int counter = dataStore.incrementCounter(keyHandleKey);
        byte userPresence = userPresenceVerifier.verifyUserPresence();
        byte[] signedData = rawMessageCodec.encodeAuthenticateSignedBytes(applicationSha256, userPresence,
                counter, challengeSha256);

        Log.info("Signing bytes " + Utils.encodeHexString(signedData));

        byte[] signature = keyPairGenerator.sign(signedData, keyPair.getPrivate());

        Log.info(" -- Outputs --");
        Log.info("  userPresence: " + userPresence);
        Log.info("  counter: " + counter);
        Log.info("  signature: " + Utils.encodeHexString(signature));

        Log.info("<< authenticate");

        return new AuthenticateResponse(userPresence, counter, signature);
    }

}
