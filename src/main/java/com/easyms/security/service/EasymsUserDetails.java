package com.easyms.security.service;

import com.google.common.annotations.VisibleForTesting;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

import static org.apache.commons.lang3.StringUtils.EMPTY;

/**
 * @author khames.
 */
@Data
public class EasymsUserDetails extends User {

    private String userId;
    private String firstName;
    private String lastName;
    private List<String> perimeters;
    private List<String> roles;

    public EasymsUserDetails(String username, String password, boolean enabled, Boolean emailValidation, List<GrantedAuthority> authorityList) {
        super(username, password, enabled, true, true, emailValidation, authorityList);
    }

    @VisibleForTesting
    public EasymsUserDetails(String username, List<GrantedAuthority> authorityList, List<String> perimeters) {
        this(username, EMPTY, true, true, authorityList);
        this.perimeters = perimeters;
    }
}
