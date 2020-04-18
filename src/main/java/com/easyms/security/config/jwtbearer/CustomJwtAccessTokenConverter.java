package com.easyms.security.config.jwtbearer;

import com.easyms.security.service.EasymsUserDetails;
import com.easyms.security.utils.TokenHelper;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;


@Slf4j
@NoArgsConstructor
public class CustomJwtAccessTokenConverter extends JwtAccessTokenConverter {

    @Setter
    private TokenHelper tokenHelper;

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        DefaultOAuth2AccessToken oAuth2AccessToken = (DefaultOAuth2AccessToken) super.enhance(accessToken, authentication);
        if (!StringUtils.containsAny(authentication.getOAuth2Request().getGrantType(), "client_credentials", "jwt-bearer")) {
            EasymsUserDetails principal = (EasymsUserDetails) authentication.getUserAuthentication().getPrincipal();
            oAuth2AccessToken.setAdditionalInformation(tokenHelper.getAdditionalInformationWithIdToken(oAuth2AccessToken, principal));
        }
        return oAuth2AccessToken;
    }
}
