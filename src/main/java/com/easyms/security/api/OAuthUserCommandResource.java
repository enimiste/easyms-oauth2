package com.easyms.security.api;

import com.easyms.security.service.OAuthUserService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author khames.
 */
@Slf4j
@RestController
@RequestMapping("/api")
@Validated
@AllArgsConstructor
public class OAuthUserCommandResource {

    private final OAuthUserService oAuthUserService;

    @GetMapping(produces = APPLICATION_JSON_VALUE, path = "/v1/users/me")
    public ResponseEntity<Map<String, Object>> me(Principal principal) {
        log.info("return authenticated user information by {}", principal.getName());
        Map<String, Object> result = oAuthUserService.buildUserInformation(principal);
        return CollectionUtils.isEmpty(result) ? ResponseEntity.badRequest().build() : ResponseEntity.ok(result);
    }
}
