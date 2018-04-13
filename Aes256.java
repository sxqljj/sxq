package com.jingantech.ngiam.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Arrays;

public class Aes256 {
    private static final String IV_STRING = "0102030405060708";
    private static volatile BouncyCastleProvider bouncyCastleProvider = null;
    public static BouncyCastleProvider getInstance() {
        if(null == bouncyCastleProvider){
            synchronized(Aes256.class){
                if(null == bouncyCastleProvider){
                    bouncyCastleProvider = new BouncyCastleProvider();
                }
            }
        }
        return bouncyCastleProvider;
    }
    public static byte[] encrypt(String key, String source) throws Exception {
        final byte[] bytes = source.getBytes("UTF8");
        return encrypt(key, bytes);
    }

    public static byte[] encrypt(String key, byte[] source) throws Exception {
        return execute(Cipher.ENCRYPT_MODE, key, source);
    }

    public static byte[] decrypt(String key, byte[] source) throws Exception {
        final byte[] bytes = execute(Cipher.DECRYPT_MODE, key, source);
        return bytes;
    }

    private static byte[] execute(int mode, String key, byte[] source) throws Exception {
        final SecretKeySpec keySpec = getKey(key);
        final byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0x00);
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Security.addProvider(getInstance());
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(mode, keySpec, ivParameterSpec);
        return cipher.doFinal(source);
    }

    private static SecretKeySpec getKey(String password) throws Exception {
        final int keyLength = 256;
        byte[] keyBytes = new byte[keyLength / 8];
        Arrays.fill(keyBytes, (byte) 0x0);
        final byte[] passwordBytes = password.getBytes("UTF-8");
        final int length = passwordBytes.length < keyBytes.length ? passwordBytes.length : keyBytes.length;
        System.arraycopy(passwordBytes, 0, keyBytes, 0, length);
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        return key;
    }

}
