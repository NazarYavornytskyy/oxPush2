/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.model;

/**
 * Enrollment request
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class EnrollmentRequest {

    private final String version;
    private final String challenge;
    private final String application;
    private final String issuer;

    public EnrollmentRequest(String version, String application, String challenge, String issuer) {
        this.version = version;
        this.challenge = challenge;
        this.application = application;
        this.issuer = issuer;
    }

    public String getVersion() {
        return version;
    }

    /**
     * The challenge parameter
     */
    public String getChallenge() {
        return challenge;
    }

    /**
     * The application parameter is the application identity of the application requesting the registration
     */
    public String getApplication() {
        return application;
    }

    /**
     * The resource server which support U2F API
     */
    public String getIssuer() {
        return issuer;
    }
}
