package com.easyms.security.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.InputStreamResource;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyPair;

/**
 * @author khames.
 */
@Configuration
public class KeyPairConfiguration {

    private static final char[] PASSWORD = "Easyms2020".toCharArray();
    private static final String ALIAS = "jwt";
    @Value("${easyms.keystore.path}")
    private String keystorePath;

    @Bean
    public KeyPair keyPair() {
        try {

            File secretsFolder = ResourceUtils.getFile("classpath:" + keystorePath);
            InputStream inputStream = new FileInputStream(secretsFolder);
            KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new InputStreamResource(inputStream), PASSWORD);
            return keyStoreKeyFactory.getKeyPair(ALIAS);
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("Cannot found private key from keystore path " + keystorePath, e);
        }
    }
}
