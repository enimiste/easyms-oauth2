package com.easyms.security.service;

import com.easyms.rest.ms.error.CommonErrorMessages;
import com.easyms.security.entity.User;
import com.easyms.security.utils.TokenHelper;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * @author khames.
 */
@Slf4j
@Service
@Transactional
@AllArgsConstructor
public class EasymsUserDetailsService implements UserDetailsService {

    private final OAuthUserService oAuthUserService;
    private final TokenHelper tokenHelper;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        Optional<User> found = oAuthUserService.findByLogin(login);
        if (!found.isPresent()) {
            log.info("User not found for login {}", login);
        }
        User user = found.orElseThrow(() -> new UsernameNotFoundException(CommonErrorMessages.bad_credentials.getErrorKey()));
        log.info("User loaded by {}, {}, {}", user.getId(), user.getLogin(), user.getRoles());
        return tokenHelper.getEasymsUserDetailsPermissions(user);
    }
}