package com.easyms.security.service;

import com.easyms.common.ms.utils.StreamUtils;
import com.easyms.security.entity.Permission;
import com.easyms.security.entity.Role;
import com.easyms.security.entity.User;
import com.easyms.security.repository.OAuthUserRepository;
import com.easyms.security.repository.RoleRepository;
import com.easyms.security.utils.TokenHelper;
import com.google.common.collect.Maps;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author khames.
 */
@Service
@Transactional
@AllArgsConstructor
public class OAuthUserService {

    private final OAuthUserRepository oAuthUserRepository;
    private final RoleRepository roleRepository;
    private final TokenHelper tokenHelper;

    public Optional<User> findByLogin(String id) {
        return oAuthUserRepository.findByLogin(id);
    }

    public Map<String, Object> buildUserInformation(Principal principal) {
        OAuth2Authentication authentication = (OAuth2Authentication) principal;
        if (Objects.isNull(authentication.getUserAuthentication())) {
            return Maps.newHashMap();
        }
        EasymsUserDetails userDetails = (EasymsUserDetails) authentication.getUserAuthentication().getPrincipal();
        return tokenHelper.buildUserInformation(userDetails);
    }

    public List<GrantedAuthority> findRolesWithPermissions(List<String> roles) {
        return tokenHelper.createAuthorityList(roles, findPermissionsByRoles(roles));
    }

    public List<String> findPermissionsByRoles(List<String> roles) {
        return StreamUtils.ofNullable(roleRepository.findByNameIn(roles))
                .filter(Objects::nonNull)
                .map(this::getPermissionsFromRole)
                .flatMap(List::stream)
                .distinct()
                .collect(Collectors.toList());
    }

    private List<String> getPermissionsFromRole(Role role) {
        return role.getPermissions().stream()
                .map(Permission::getName)
                .collect(Collectors.toList());
    }
}
