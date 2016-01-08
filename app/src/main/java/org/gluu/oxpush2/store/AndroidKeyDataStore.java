/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.store;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * Provides methods to store key pair in application preferences
 *
 * Created by Yuriy Movchan on 12/28/2015.
 */
public class AndroidKeyDataStore {

    private static final String U2F_KEY_PAIR_FILE = "u2f_key_pairs";
    private static final String U2F_KEY_COUNT_FILE = "u2f_key_counts";

    private static final boolean DEBUG = true;
    private static final String TAG = AndroidKeyDataStore.class.getName();
    private final Context context;

    public AndroidKeyDataStore(Context context) {
        this.context = context;

        // Prepare empty U2F key pair store
        final SharedPreferences keySettings = context.getSharedPreferences(U2F_KEY_PAIR_FILE, Context.MODE_PRIVATE);
        if (keySettings.getAll().size() == 0) {
            if (DEBUG) Log.d(TAG, "Creating empty U2K key pair store");
            keySettings.edit().commit();
        }

        // Prepare empty U2F key counter store
        final SharedPreferences keyCounts = context.getSharedPreferences(U2F_KEY_COUNT_FILE, Context.MODE_PRIVATE);
        if (keyCounts.getAll().size() == 0) {
            if (DEBUG) Log.d(TAG, "Creating empty U2K key counter store");
            keyCounts.edit().commit();
        }
    }

    public void storeKeyPair(String keyHandle, String keyPair) {
        if (DEBUG) Log.d(TAG, "Storing new keyHandle: " + keyHandle + " with keyPair: " + keyPair);
        final SharedPreferences keySettings = context.getSharedPreferences(U2F_KEY_PAIR_FILE, Context.MODE_PRIVATE);
        keySettings.edit().putString(keyHandle, keyPair).commit();

        final SharedPreferences keyCounts = context.getSharedPreferences(U2F_KEY_COUNT_FILE, Context.MODE_PRIVATE);
        keyCounts.edit().putInt(keyHandle, 0).commit();
    }

    public String getKeyPair(String keyHandle) {
        if (DEBUG) Log.d(TAG, "Getting keyPair by keyHandle: " + keyHandle);

        final SharedPreferences keySettings = context.getSharedPreferences(U2F_KEY_PAIR_FILE, Context.MODE_PRIVATE);
        String keyPair = keySettings.getString(keyHandle, null);

        if (DEBUG) Log.d(TAG, "Found keyPair " + keyPair + " by keyHandle: " + keyHandle);

        return keyPair;
    }


    public int incrementCounter(String keyHandle) {
        if (DEBUG) Log.d(TAG, "Incrementing keyHandle: " + keyHandle + " counter");

        final SharedPreferences keyCounts = context.getSharedPreferences(U2F_KEY_COUNT_FILE, Context.MODE_PRIVATE);

        int currentCounter = keyCounts.getInt(keyHandle, -1);
        currentCounter++;

        keyCounts.edit().putInt(keyHandle, currentCounter).commit();

        if (DEBUG) Log.d(TAG, "Counter is " + currentCounter + " for keyHandle: " + keyHandle + " counter");

        return currentCounter;
    }

}