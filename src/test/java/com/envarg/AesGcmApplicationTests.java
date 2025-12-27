package com.envarg;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import com.envarg.service.AesGcmService;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(
    classes = AesGcmApplicationTests.TestConfig.class,
    properties = {
        "app.aes-gcm.enabled=true",
        "app.aes-gcm.secret=rBm/L0MsvQqX2adVQLU072edfzkyCCH0pPTtt+kIL0s=",
        "app.aes-gcm.version=1"
    }
)
class AesGcmApplicationTests {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private AesGcmService aesGcmService;

    @Test
    void contextLoads() {
        assertNotNull(applicationContext);
    }

    @Test
    void aesGcmServiceBeanInjected() {
        assertNotNull(aesGcmService);
    }

    @Test
    void encryptDecryptRoundTrip() {
        String plaintext = "test-data";
        String encrypted = aesGcmService.encrypt(plaintext);
        String decrypted = aesGcmService.decrypt(encrypted);
        
        assertNotNull(encrypted);
        assertEquals(plaintext, decrypted);
    }

    @Configuration
    @EnableAutoConfiguration
    static class TestConfig {
    }
}
