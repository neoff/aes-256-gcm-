package com.envarg.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Setter
@Getter
@Validated
@ConfigurationProperties("app.aes-gcm")
public class AesGcmProperties {

  /**
   * Enable AES-GCM encryption/decryption service.
   */
  private boolean enabled = true;

  /**
   * Base64-encoded 32-byte AES secret key.
   * Generate with: openssl rand -base64 32
   */
  @NotBlank
  private String secret;

  /**
   * Key version for blob tagging (supports key rotation).
   */
  @Positive
  private int version = 1;

}
