package com.easyms.security.utils;

import com.easyms.security.entity.Permission;
import com.easyms.security.entity.Role;
import com.easyms.security.entity.User;
import com.easyms.security.service.EasymsUserDetails;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.easyms.security.utils.Constants.*;

/**
 * @author khames.
 */
@Component
@RequiredArgsConstructor
public class TokenHelper {

    private final ObjectMapper objectMapper;
    private final KeyPair keyPair;

    public Map<String, Object> getAdditionalInformationWithIdToken(OAuth2AccessToken accessToken, EasymsUserDetails user) {
        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
        Map<String, Object> additionalInfo = Maps.newHashMap();
        additionalInfo.putAll(additionalInformation);
        additionalInfo.put(ID_TOKEN, generateIdToken(buildUserInformation(user)));
        return additionalInfo;
    }

    public Map<String, Object> buildUserInformation(EasymsUserDetails userDetails) {
        Map<String, Object> map = Maps.newHashMap();
        map.put(SUB, userDetails.getUserId());
        map.put(LOGIN, userDetails.getUsername());
        map.put(ROLES, userDetails.getRoles());
        map.put(PERIMETERS, userDetails.getPerimeters());
        map.put(FIRST_NAME, userDetails.getFirstName());
        map.put(LAST_NAME, userDetails.getLastName());

        return map;
    }

    public List<GrantedAuthority> createAuthorityList(List<String> roles, List<String> permissions) {
        List<GrantedAuthority> authorities = Optional.ofNullable(roles).orElse(Lists.newArrayList()).stream()
                .filter(StringUtils::isNotBlank)
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                .collect(Collectors.toList());

        authorities.addAll(Optional.ofNullable(permissions).orElse(Lists.newArrayList()).stream()
                .filter(StringUtils::isNotBlank)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));

        return authorities;
    }

    public EasymsUserDetails getEasymsUserDetailsPermissions(User user) {
        List<GrantedAuthority> authorities = createAuthorityList(getRolesName(user), getPermissionsName(user));
        return buildEasymsUserDetails(user, authorities);
    }

    private EasymsUserDetails buildEasymsUserDetails(User user, List<GrantedAuthority> authorities) {
        EasymsUserDetails userDetails = new EasymsUserDetails(user.getLogin(), user.getPassword(), user.isEnabled(), user.isEnabled(), authorities);
        userDetails.setUserId(user.getId().toString());
        userDetails.setRoles(getRolesName(user));
        userDetails.setPerimeters(user.getPerimetersAsList());
        return userDetails;
    }

    private List<String> getPermissionsName(User user) {
        return user.getRoles()
                .stream()
                .flatMap(p -> p.getPermissions().stream())
                .map(Permission::getName)
                .collect(Collectors.toList());
    }

    private List<String> getRolesName(User user) {
        return user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.toList());
    }

    private String generateIdToken(Map<String, Object> idTokenMap) {
        try {
            String content = objectMapper.writeValueAsString(idTokenMap);
            return JwtHelper.encode(content, getSigner()).getEncoded();
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot format token id map to JSON", e);
        }
    }

    private RsaSigner getSigner() {
        return new RsaSigner((RSAPrivateKey) keyPair.getPrivate());
    }
}
