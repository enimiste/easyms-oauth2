package com.easyms.security.utils;

import com.easyms.security.entity.Permission;
import com.easyms.security.entity.Role;
import com.easyms.security.entity.User;
import com.easyms.security.service.EasymsUserDetails;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.easyms.security.utils.Constants.*;

/**
 * @author khames.
 */
@Component
public class TokenHelper {

    public Map<String, Object> buildUserInformation(EasymsUserDetails userDetails) {
        Map<String, Object> map = Maps.newHashMap();
        map.put(SUB, userDetails.getUserId());
        map.put(LOGIN, userDetails.getUsername());
        map.put(ROLES, userDetails.getRoles());
        map.put(PERIMETERS, userDetails.getPerimeters());
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
}
