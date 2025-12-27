package com.envarg.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import com.envarg.config.properties.AesGcmProperties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AesGcmAutoConfigurationDisabledTest {

  private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
      .withUserConfiguration(AesGcmAutoConfiguration.class);

  @Test
  void whenDisabled_beansNotCreated() {
    contextRunner
        .withPropertyValues(
            "app.aes-gcm.enabled=false",
            "app.aes-gcm.secret=rBm/L0MsvQqX2adVQLU072edfzkyCCH0pPTtt+kIL0s="
        )
        .run(context -> {
          assertThrows(NoSuchBeanDefinitionException.class, 
              () -> context.getBean("aesGcmService"));
        });
  }

  @Test
  void whenEnabled_beansCreated() {
    contextRunner
        .withPropertyValues(
            "app.aes-gcm.enabled=true",
            "app.aes-gcm.secret=rBm/L0MsvQqX2adVQLU072edfzkyCCH0pPTtt+kIL0s=",
            "app.aes-gcm.version=1"
        )
        .run(context -> {
          assertNotNull(context.getBean("aesGcmService"));
          assertNotNull(context.getBean("aesGcmSecretKey"));
        });
  }

  @Test
  void whenInvalidKeyLength_throwsException() {
    contextRunner
        .withPropertyValues(
            "app.aes-gcm.enabled=true",
            "app.aes-gcm.secret=c2hvcnRrZXk=",  // "shortkey" - only 8 bytes
            "app.aes-gcm.version=1"
        )
        .run(context -> {
          assertNotNull(context.getStartupFailure());
          assertTrue(context.getStartupFailure().getMessage().contains("32 bytes"));
        });
  }

  @Test
  void propertiesGettersAndSetters() {
    AesGcmProperties props = new AesGcmProperties();
    
    props.setEnabled(false);
    assertFalse(props.isEnabled());
    
    props.setEnabled(true);
    assertTrue(props.isEnabled());
    
    props.setSecret("test-secret");
    assertEquals("test-secret", props.getSecret());
    
    props.setVersion(42);
    assertEquals(42, props.getVersion());
  }
}
