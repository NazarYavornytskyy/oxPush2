/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.cert;

import org.gluu.oxpush2.u2f.v2.exception.U2FException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Service to work generate key pair  and other crypto methods
 *
 * Created by Yuriy Movchan on 12/07/2015.
 */
public interface KeyPairGenerator {

    KeyPair generateKeyPair(byte[] applicationSha256, byte[] challengeSha256);

    byte[] sign(byte[] signedData, PrivateKey certificatePrivateKey) throws U2FException;

    byte[] generateKeyHandle(byte[] applicationSha256);

    byte[] encodePublicKey(PublicKey publicKey);

    String keyPairToJson(KeyPair keyPair);

    KeyPair keyPairFromJson(String keyPairJson);

    String keyHandleToKey(byte[] keyHandle);

}
