/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.u2f.v2.store;

import org.gluu.oxpush2.store.AndroidKeyDataStore;

/**
 * Service to work with key pair store
 *
 * Created by Yuriy Movchan on 07/12/2015.
 */
public class DataStoreImpl implements DataStore {

    private final AndroidKeyDataStore keyDataStore;

    public DataStoreImpl(AndroidKeyDataStore keyDataStore) {
        this.keyDataStore = keyDataStore;
    }

    @Override
    public void storeKeyPair(String keyHandle, String keyPair) {
        this.keyDataStore.storeKeyPair(keyHandle, keyPair);
    }

    @Override
    public String getKeyPair(String keyHandle) {
        return this.keyDataStore.getKeyPair(keyHandle);
    }

    @Override
    public int incrementCounter(String keyHandle) {
        return this.keyDataStore.incrementCounter(keyHandle);
    }

}
