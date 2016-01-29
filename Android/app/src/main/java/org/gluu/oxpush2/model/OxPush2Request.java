/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.model;

import com.google.gson.annotations.SerializedName;

/**
 * oxPush2 request
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class OxPush2Request {

    @SerializedName("username")
    private String userName;

    private String issuer;

    private String app;

    private String state;

    private String method;

    private String created;

    public OxPush2Request() {
    }

    public OxPush2Request(String userName, String issuer, String app, String state, String method, String created) {
        this.userName = userName;
        this.issuer = issuer;
        this.app = app;
        this.state = state;
        this.method = method;
        this.created = created;
    }

    public String getUserName() {
        return userName;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getApp() {
        return app;
    }

    public String getState() {
        return state;
    }

    public String getMethod() {
        return method;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getCreated() {
        return created;
    }
}
