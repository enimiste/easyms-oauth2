package com.easyms.security.service;

import com.easyms.common.ms.error.CommonErrorMessages;
import com.easyms.security.config.OAuthProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * @author khames.
 */
@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ClientService implements ClientDetailsService {

    private final OAuthProperties properties;
    private final OAuthUserService oAuthUserService;

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        OAuthProperties.OAuthClientDetails oAuthClientDetails = properties.getOAuthClients().get(clientId);
        if (Objects.isNull(oAuthClientDetails)) {
            log.error("No client with requested id " + clientId);
            throw new AccessDeniedException(CommonErrorMessages.access_denied.getErrorKey());
        }

        if (!oAuthClientDetails.isEnabled()) {
            log.error("Client {} is disabled", clientId);
            throw new AccessDeniedException(CommonErrorMessages.access_denied.getErrorKey());
        }

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(oAuthClientDetails.getClientSecret());
        clientDetails.setScope(Collections.singletonList("Easyms"));
        List<GrantedAuthority> authorities = Optional.ofNullable(oAuthClientDetails.getAuthorities()).map(oAuthUserService::findRolesWithPermissions).orElse(Collections.emptyList());
        clientDetails.setAuthorities(authorities);
        clientDetails.setAutoApproveScopes(Collections.singletonList("Easyms"));
        clientDetails.setAuthorizedGrantTypes(oAuthClientDetails.getAuthorizedGrantTypes());
        clientDetails.setRegisteredRedirectUri(oAuthClientDetails.getRegisteredRedirectUris());
        Optional.ofNullable(oAuthClientDetails.getAccessTokenValidity()).ifPresent(clientDetails::setAccessTokenValiditySeconds);
        Optional.ofNullable(oAuthClientDetails.getRefreshTokenValidity()).ifPresent(clientDetails::setRefreshTokenValiditySeconds);

        log.debug("Load Client by client id {}, {} " + clientId, clientDetails.toString());
        return clientDetails;
    }
}
