package com.envarg.utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AesGcmDecoderTest {
  
  @Test
  void encryptDecrypt_roundTrip_randomIv() {
    var key32 = key32();
    byte[] pt = "hello-gcm".getBytes();
    AesGcmDecoder.AeadBlob blob = AesGcmDecoder.encrypt(pt, new SecureRandom(), key32, 1);
    assertNotNull(blob.iv());
    assertEquals(AesGcmDecoder.IV_BYTES, blob.iv().length);
    assertEquals(AesGcmDecoder.GCM_TAG_BYTES, blob.tag().length);
    assertEquals(1, blob.keyVersion());
    
    byte[] back = AesGcmDecoder.decrypt(blob, key32);
    assertArrayEquals(pt, back);
  }

  @Test
  void encryptDecrypt_string_roundTrip() {
    var key32 = key32();
    String plaintext = "hello-world-тест";
    
    String encrypted = AesGcmDecoder.encrypt(plaintext, new SecureRandom(), key32, 1);
    String decrypted = AesGcmDecoder.decrypt(encrypted, key32, 1);
    
    assertEquals(plaintext, decrypted);
  }
  
  @Test
  void encryptWithFixedIv_deterministic() {
    var key32 = key32();
    byte[] pt = "deterministic".getBytes();
    byte[] iv = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    
    AesGcmDecoder.AeadBlob blob = AesGcmDecoder.encryptWithIv(pt, iv, key32, 1);
    
    assertArrayEquals(iv, blob.iv());
    // Повторный вызов с тем же IV и ключом должен давать тот же ct/tag
    AesGcmDecoder.AeadBlob blob2 = AesGcmDecoder.encryptWithIv(pt, iv, key32, 1);
    assertArrayEquals(blob.ct(), blob2.ct());
    assertArrayEquals(blob.tag(), blob2.tag());
  }
  
  @Test
  void tamper_tagFails() {
    var key32 = key32();
    byte[] pt = "attack-at-dawn".getBytes();
    AesGcmDecoder.AeadBlob blob = AesGcmDecoder.encrypt(pt, new SecureRandom(), key32, 1);
    
    byte[] badTag = blob.tag().clone();
    badTag[0] ^= 0xFF;
    AesGcmDecoder.AeadBlob tampered = new AesGcmDecoder.AeadBlob(blob.ct(), blob.iv(), badTag, blob.keyVersion());
    
    assertThrows(SecurityException.class, () -> AesGcmDecoder.decrypt(tampered, key32));
  }
  
  @Test
  void packUnpack_roundTrip() {
    AesGcmDecoder.AeadBlob b =
        new AesGcmDecoder.AeadBlob(
            new byte[] {1, 2, 3, 4, 5},
            new byte[] {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21},
            new byte[] {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
            7);

    String s = AesGcmDecoder.pack(b);
    AesGcmDecoder.AeadBlob back = AesGcmDecoder.unpack(s);

    assertEquals(7, back.keyVersion());
    assertArrayEquals(b.iv(), back.iv());
    assertArrayEquals(b.tag(), back.tag());
    assertArrayEquals(b.ct(), back.ct());
  }

  @Test
  void unpack_badMagic_throws() {
    // Create blob with wrong magic bytes (not 'AG')
    ByteBuffer buf = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
    buf.put((byte) 'X');  // wrong magic
    buf.put((byte) 'Y');
    buf.put((byte) 1);    // version
    buf.putShort((short) 1);  // key version
    buf.put((byte) 2);    // iv len
    buf.put((byte) 2);    // tag len
    buf.put(new byte[] {1, 2});  // iv
    buf.put(new byte[] {3, 4});  // tag
    buf.put(new byte[] {5, 6, 7});  // ct
    
    String packed = Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
    
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
        () -> AesGcmDecoder.unpack(packed));
    assertTrue(ex.getMessage().contains("Bad magic"));
  }

  @Test
  void unpack_unsupportedVersion_throws() {
    // Create blob with unsupported format version
    ByteBuffer buf = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
    buf.put((byte) 'A');
    buf.put((byte) 'G');
    buf.put((byte) 99);   // unsupported version
    buf.putShort((short) 1);
    buf.put((byte) 2);
    buf.put((byte) 2);
    buf.put(new byte[] {1, 2});
    buf.put(new byte[] {3, 4});
    buf.put(new byte[] {5, 6, 7});
    
    String packed = Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
    
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
        () -> AesGcmDecoder.unpack(packed));
    assertTrue(ex.getMessage().contains("Unsupported format version"));
  }

  @Test
  void unpack_corruptedBlob_throws() {
    // Create blob that claims more data than available
    ByteBuffer buf = ByteBuffer.allocate(10).order(ByteOrder.BIG_ENDIAN);
    buf.put((byte) 'A');
    buf.put((byte) 'G');
    buf.put((byte) 1);    // version
    buf.putShort((short) 1);  // key version
    buf.put((byte) 100);  // iv len - way too large
    buf.put((byte) 100);  // tag len - way too large
    buf.put(new byte[] {1, 2, 3});  // not enough data
    
    String packed = Base64.getUrlEncoder().withoutPadding().encodeToString(buf.array());
    
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
        () -> AesGcmDecoder.unpack(packed));
    assertTrue(ex.getMessage().contains("Corrupted blob"));
  }

  @Test
  void decrypt_wrongKeyVersion_throws() {
    var key32 = key32();
    String encrypted = AesGcmDecoder.encrypt("test", new SecureRandom(), key32, 1);
    
    IllegalStateException ex = assertThrows(IllegalStateException.class, 
        () -> AesGcmDecoder.decrypt(encrypted, key32, 2));  // wrong version
    assertTrue(ex.getMessage().contains("Unexpected key version"));
  }

  public static SecretKey key32() {
    byte[] k = new byte[32];
    for (int i = 0; i < 32; i++) {
      k[i] = (byte) (i + 1);
    }
    return new SecretKeySpec(k, "AES");
  }
}
