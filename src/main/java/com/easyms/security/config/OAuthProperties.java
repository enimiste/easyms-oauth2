package com.easyms.security.config;

import com.google.common.collect.Maps;
import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author khames.
 */
@Getter
@Configuration
@ConfigurationProperties("easyms")
public class OAuthProperties {

    private final Token token = new Token();
    private final Map<String, OAuthClientDetails> oAuthClients = Maps.newHashMap();

    @Data
    public static class Token {
        private Integer expirationTime;
    }

    @Data
    public static class OAuthClientDetails {
        private String clientSecret;
        private List<String> authorities;
        private List<String> authorizedGrantTypes;
        private Integer accessTokenValidity;
        private Integer refreshTokenValidity;
        private boolean enabled = true;
        private Set<String> registeredRedirectUris;
    }

}
