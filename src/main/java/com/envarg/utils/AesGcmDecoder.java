package com.envarg.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class AesGcmDecoder {
  public static final int GCM_TAG_BYTES = 16;
  public static final int IV_BYTES = 12;
  private static final byte[] MAGIC = new byte[] {'A', 'G'};
  private static final byte FORMAT_VER = 1;

  /**
   * Immutable AEAD blob containing ciphertext, IV, tag, and key version.
   * All byte arrays are defensively copied on construction and access.
   */
  public static final class AeadBlob {
    private final byte[] ct;
    private final byte[] iv;
    private final byte[] tag;
    private final int keyVersion;

    public AeadBlob(byte[] ct, byte[] iv, byte[] tag, int keyVersion) {
      this.ct = ct.clone();
      this.iv = iv.clone();
      this.tag = tag.clone();
      this.keyVersion = keyVersion;
    }

    public byte[] ct() {
      return ct.clone();
    }

    public byte[] iv() {
      return iv.clone();
    }

    public byte[] tag() {
      return tag.clone();
    }

    public int keyVersion() {
      return keyVersion;
    }
  }

  private AesGcmDecoder() {}
  
  /**
   * Pack AEAD blob into its base64 string representation.
   * @param b blob to pack
   * @return packed blob
   */
  public static String pack(AeadBlob b) {
    byte[] iv = b.iv();
    byte[] tag = b.tag();
    byte[] ct = b.ct();
    
    int len = 7 + iv.length + tag.length + ct.length;
    
    ByteBuffer buf = ByteBuffer.allocate(len).order(ByteOrder.BIG_ENDIAN);
    buf.put(MAGIC);
    buf.put(FORMAT_VER);
    buf.putShort((short) b.keyVersion());
    buf.put((byte) iv.length);
    buf.put((byte) tag.length);
    buf.put(iv);
    buf.put(tag);
    buf.put(ct);
    
    return Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
  }
  
  /**
   * Unpack AEAD blob from base64 string representation.
   *
   * @param packed packed blob
   * @return unpacked blob
   * @throws IllegalArgumentException if the packed blob is corrupted or has unsupported format
   *     version
   */
  public static AeadBlob unpack(String packed) {
    byte[] raw = Base64.getUrlDecoder().decode(packed);
    ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
    
    if (buf.get() != 'A' || buf.get() != 'G') {
      throw new IllegalArgumentException("Bad magic");
    }
    
    byte ver = buf.get();
    if (ver != FORMAT_VER) {
      throw new IllegalArgumentException("Unsupported format version: " + ver);
    }
    
    short kv = buf.getShort();
    int ivLen = Byte.toUnsignedInt(buf.get());
    int tagLen = Byte.toUnsignedInt(buf.get());
    
    if (buf.remaining() < ivLen + tagLen + 1) {
      throw new IllegalArgumentException("Corrupted blob");
    }
    
    byte[] iv = new byte[ivLen];
    buf.get(iv);
    int keyVer = Short.toUnsignedInt(kv);
    byte[] tag = new byte[tagLen];
    buf.get(tag);
    byte[] ct = new byte[buf.remaining()];
    buf.get(ct);
    
    return new AeadBlob(ct, iv, tag, keyVer);
  }
  
  public static String encrypt(String plaintext, SecureRandom random, SecretKey key, Integer keyVersion) {
    AeadBlob blob = encrypt(plaintext.getBytes(StandardCharsets.UTF_8), random, key, keyVersion);
    return pack(blob);
  }
  
  public static AeadBlob encrypt(byte[] plaintext, SecureRandom random, SecretKey key, Integer keyVersion) {
    byte[] iv = new byte[IV_BYTES];
    random.nextBytes(iv);
    return encryptWithIv(plaintext, iv, key, keyVersion);
  }
  
  public static AeadBlob encryptWithIv(byte[] plaintext, byte[] iv, SecretKey key, Integer keyVersion) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BYTES * 8, iv));
      byte[] out = cipher.doFinal(plaintext);
      int ctLen = out.length - GCM_TAG_BYTES;
      byte[] ct = Arrays.copyOf(out, ctLen);
      byte[] tag = Arrays.copyOfRange(out, ctLen, out.length);
      return new AeadBlob(ct, iv, tag, keyVersion);
    } catch (GeneralSecurityException e) { // NOPMD - unreachable, AES/GCM always available
      throw new SecurityException("AES-GCM encrypt failed", e); // $COVERAGE-IGNORE$
    }
  }
  
  public static String decrypt(String columnValue, SecretKey key, Integer keyVersion) {
    AeadBlob blob = unpack(columnValue);
    if (blob.keyVersion() != keyVersion) {
      throw new IllegalStateException("Unexpected key version " + blob.keyVersion());
    }
    return new String(decrypt(blob, key), StandardCharsets.UTF_8);
  }
  
  public static byte[] decrypt(AeadBlob blob, SecretKey key) {
    try {
      byte[] combined = new byte[blob.ct().length + blob.tag().length];
      System.arraycopy(blob.ct(), 0, combined, 0, blob.ct().length);
      System.arraycopy(blob.tag(), 0, combined, blob.ct().length, blob.tag().length);
      
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BYTES * 8, blob.iv()));
      return cipher.doFinal(combined);
    } catch (AEADBadTagException e) {
      throw new SecurityException("AES-GCM auth failed", e);
    } catch (GeneralSecurityException e) { // NOPMD - unreachable, AES/GCM always available
      throw new SecurityException("AES-GCM decrypt failed", e); // $COVERAGE-IGNORE$
    }
  }
}
