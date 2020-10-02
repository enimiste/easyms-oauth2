package com.easyms.security.config;

import com.easyms.security.config.jwtbearer.JwtBearerTokenGranter;
import com.easyms.security.service.ClientService;
import com.easyms.security.service.EasymsUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class OAuthTokenConfiguration {


    private final ClientService clientService;
    private final EasymsUserDetailsService easymsUserDetailsService;
    private final OAuthProperties properties;
    private final KeyPair keyPair;


    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverterFromKeyPair(UserAuthenticationConverter userAuthenticationConverter) throws InvalidKeySpecException, NoSuchAlgorithmException, CertificateException {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(loadKeyPair());
        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(userAuthenticationConverter);
        jwtAccessTokenConverter.setAccessTokenConverter(defaultAccessTokenConverter);
        return jwtAccessTokenConverter;
    }

    private KeyPair loadKeyPair() throws InvalidKeySpecException, NoSuchAlgorithmException, CertificateException {
        if(properties.getOAuthPemEnabled() != null && properties.getOAuthPemEnabled()) {
            PublicKey publicKey = getPublicKey(loadPubFromPem(properties.getOAuthPemPrivateKey()));
            PrivateKey privateKey = getPrivateKey(loadPrivateFromPem(properties.getOAuthPemPrivateKey()));
            return new KeyPair(publicKey, privateKey);
        }  else {
            return keyPair;
        }
    }

    @Bean
    public TokenStore tokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
        return new JwtTokenStore(jwtAccessTokenConverter);
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices(JwtAccessTokenConverter jwtAccessTokenConverter, TokenStore tokenStore) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setReuseRefreshToken(false);
        tokenServices.setClientDetailsService(clientService);
        tokenServices.setTokenEnhancer(jwtAccessTokenConverter);
        tokenServices.setAccessTokenValiditySeconds(properties.getToken().getExpirationTime());
        return tokenServices;
    }


    @Bean
    public CustomUserAuthenticationConverter userAuthenticationConverter() {
        CustomUserAuthenticationConverter userAuthenticationConverter = new CustomUserAuthenticationConverter();
        userAuthenticationConverter.setUserDetailsService(easymsUserDetailsService);
        return userAuthenticationConverter;
    }




    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private byte[] loadPrivateFromPem(String pem) {
        String[] tPem =  pem.split("-----END PRIVATE KEY-----");
        pem = tPem[0].replace("-----BEGIN PRIVATE KEY-----", "").replaceAll("\n","");
        return Base64.getMimeDecoder().decode(pem);
    }

    private byte[] loadPubFromPem(String pem) {
        String[] tPem =  pem.split("-----BEGIN CERTIFICATE-----");
        pem = tPem[1].replace("-----END CERTIFICATE-----", "").replaceAll("\n","");
        return Base64.getMimeDecoder().decode(pem);
    }

    private PrivateKey getPrivateKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey getPublicKey(byte[] keyBytes) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(keyBytes));
        return certificate.getPublicKey();
    }
}
