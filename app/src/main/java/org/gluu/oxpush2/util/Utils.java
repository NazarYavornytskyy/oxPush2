/*
 *  oxPush2 is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 *  Copyright (c) 2014, Gluu
 */

package org.gluu.oxpush2.util;

import android.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.Arrays;

/**
 * Utility methods
 *
 * Created by Yuriy Movchan on 12/07/2015.
 */
public class Utils {

    public static boolean equals(Object a, Object b) {
        return (a == b) || (a != null && a.equals(b));
    }

    public static int hash(Object... values) {
        return Arrays.hashCode(values);
    }

    public static String base64UrlEncode(byte[] arg) {
        return Base64.encodeToString(arg, 0, arg.length, Base64.URL_SAFE | Base64.NO_WRAP);
    }

    public static byte[] base64UrlDecode(String arg) {
        return Base64.decode(arg, Base64.URL_SAFE | Base64.NO_WRAP);
    }

    public static String encodeHexString(byte[] arg) {
        return new String(Hex.encodeHex(arg));
    }

    public static byte[] decodeHexString(String arg) throws DecoderException {
        return Hex.decodeHex(arg.toCharArray());
    }

}
