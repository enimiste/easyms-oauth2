package com.easyms.security.config;

import com.easyms.security.service.EasymsUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.Map;

import static com.easyms.security.utils.Constants.PERIMETERS;

/**
 * @author khames.
 */
public class CustomUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = (Map<String, Object>) super.convertUserAuthentication(authentication);
        EasymsUserDetails principal = (EasymsUserDetails) authentication.getPrincipal();
        response.put(PERIMETERS, principal.getPerimeters());
        return response;
    }
}
