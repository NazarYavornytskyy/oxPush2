/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.store;

/**
 * Service to work with key pair store
 *
 * Created by Yuriy Movchan on 07/12/2015.
 */
public interface DataStore {

    void storeKeyPair(String keyHandle, String keyPair);

    String getKeyPair(String keyHandle);

    int incrementCounter(String keyHandle);

}
