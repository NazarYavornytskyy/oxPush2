/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.model;

import org.gluu.oxpush2.util.Utils;

import java.util.Arrays;

/**
 * Enrollment request
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class EnrollmentRequest {

    private final byte[] challengeSha256;
    private final byte[] applicationSha256;

    public EnrollmentRequest(byte[] applicationSha256, byte[] challengeSha256) {
        this.challengeSha256 = challengeSha256;
        this.applicationSha256 = applicationSha256;
    }

    /**
     * The challenge parameter is the SHA-256 hash of the Client Data, a
     * stringified JSON datastructure that the FIDO Client prepares. Among other
     * things, the Client Data contains the challenge from the relying party
     * (hence the name of the parameter). See below for a detailed explanation of
     * Client Data.
     */
    public byte[] getChallengeSha256() {
        return challengeSha256;
    }

    /**
     * The application parameter is the SHA-256 hash of the application identity
     * of the application requesting the registration
     */
    public byte[] getApplicationSha256() {
        return applicationSha256;
    }

    @Override
    public int hashCode() {
        return Utils.hash(applicationSha256, challengeSha256);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        EnrollmentRequest other = (EnrollmentRequest) obj;
        return Arrays.equals(applicationSha256, other.applicationSha256)
                && Arrays.equals(challengeSha256, other.challengeSha256);
    }

}
