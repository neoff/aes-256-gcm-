# AES-256-GCM Encryption Library

Spring Boot library providing AES-256-GCM authenticated encryption (AEAD).

## Versions

| Version | Java | Spring Boot | Branch |
|---------|------|-------------|--------|
| 1.x | 11 | 2.4.x | `v1.x` |
| 2.x | 17+ | 3.x | `main` |

## Installation

### Maven

```xml
<dependency>
    <groupId>com.envarg</groupId>
    <artifactId>aes-256-gcm</artifactId>
    <version>2.0.0</version> <!-- or 1.0.0 for Java 11 -->
</dependency>
```

## Usage

### 1. Standalone (without Spring)

```java
import com.envarg.utils.AesGcmDecoder;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

// Create key (32 bytes for AES-256)
byte[] keyBytes = Base64.getDecoder().decode("your-base64-encoded-32-byte-key");
SecretKey key = new SecretKeySpec(keyBytes, "AES");
SecureRandom random = new SecureRandom();
int keyVersion = 1;

// Encrypt
String encrypted = AesGcmDecoder.encrypt("sensitive data", random, key, keyVersion);

// Decrypt
String decrypted = AesGcmDecoder.decrypt(encrypted, key, keyVersion);
```

Generate a secret key:
```bash
openssl rand -base64 32
```

### 2. Spring Boot Starter

The library auto-configures when added to classpath.

#### Configuration

```yaml
app:
  aes-gcm:
    enabled: true                    # enable/disable (default: true)
    secret: ${AES_GCM_SECRET}        # Base64-encoded 32-byte key
    version: ${AES_GCM_VERSION:1}    # key version for rotation support
```

#### Usage

```java
@Service
@RequiredArgsConstructor
public class MyService {
    
    private final AesGcmService aesGcmService;
    
    public void process() {
        String encrypted = aesGcmService.encrypt("sensitive data");
        String decrypted = aesGcmService.decrypt(encrypted);
    }
}
```

#### Disabling Auto-Configuration

```yaml
app:
  aes-gcm:
    enabled: false
```

## Binary Blob Format

Encrypted data is represented as URL-safe Base64:

```
[MAGIC:2b][VERSION:1b][KEY_VER:2b][IV_LEN:1b][TAG_LEN:1b][IV:12b][TAG:16b][CIPHERTEXT:Nb]
```

| Field | Size | Description |
|-------|------|-------------|
| MAGIC | 2 bytes | Magic bytes \`AG\` |
| VERSION | 1 byte | Format version (current: 1) |
| KEY_VER | 2 bytes | Encryption key version |
| IV_LEN | 1 byte | IV length (12) |
| TAG_LEN | 1 byte | Authentication tag length (16) |
| IV | 12 bytes | Initialization Vector |
| TAG | 16 bytes | GCM Authentication Tag |
| CIPHERTEXT | N bytes | Encrypted data |

## License

MIT
