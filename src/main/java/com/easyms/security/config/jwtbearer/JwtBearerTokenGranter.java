package com.easyms.security.config.jwtbearer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;

import java.util.Map;

/**
     * @author abessa.
 */
@Slf4j
public class JwtBearerTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "jwt-bearer";
    private ClientDetailsService clientDetailsService;
    private ObjectMapper objectMapper;
    private RsaVerifier rsaVerifier;

    public JwtBearerTokenGranter(AuthorizationServerEndpointsConfigurer endpoints, ObjectMapper objectMapper, String publicKey) {
        super(endpoints.getTokenServices(), endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory(), GRANT_TYPE);
        this.objectMapper = objectMapper;
        this.rsaVerifier = new RsaVerifier(publicKey);
        this.clientDetailsService = endpoints.getClientDetailsService();
    }

    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        String assertion = tokenRequest.getRequestParameters().get("assertion");
        if (StringUtils.isBlank(assertion)) {
            throw new InvalidRequestException("Missing assertion");
        }
        Map<String, String> claims = getClaims(assertion);
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(claims.get("sub"));
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(clientDetails, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, null);
    }

    private Map<String, String> getClaims(String assertion) {
        try {
            Jwt jwt = JwtHelper.decodeAndVerify(assertion, rsaVerifier);
            return objectMapper.readValue(jwt.getClaims(), new TypeReference<Map<String, String>>() {
            });
        } catch (Exception e) {
            log.error("Error while extracting claims from assertion token : {}", e.getMessage());
            throw new InvalidRequestException("Invalid assertion");
        }
    }
}
