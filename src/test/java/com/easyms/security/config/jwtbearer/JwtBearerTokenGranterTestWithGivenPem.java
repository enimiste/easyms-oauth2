package com.easyms.security.config.jwtbearer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.ResourceUtils;

import javax.inject.Inject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@AutoConfigureMockMvc
@SpringBootTest
@ActiveProfiles("test,securitytests,givenpem")
class JwtBearerTokenGranterTestWithGivenPem {

    private static final String TOKEN_URL = "/oauth/token";
    private static final String ME_URL = "/api/v1/users/me";
    @Inject
    protected MockMvc mockMvc;

    private static final char[] PASSWORD = "Easyms2020".toCharArray();
    private static final String ALIAS = "jwt";

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TOKEN_TYPE = "Bearer";

    @Inject
    ObjectMapper objectMapper;

    @Test
    void should_return_token_with_password_credentials_with_given_pem() throws Exception {
        String userName = "admin-client@yopmail.com";
        String contentAsString = mockMvc.perform(post(TOKEN_URL)
                .param("client_id", "testClient")
                .param("client_secret", "secret")
                .param("grant_type", "password")
                .param("password", "password")
                .param("username", userName)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token", Matchers.notNullValue()))
                .andReturn().getResponse().getContentAsString();

        String accessToken = JsonPath.read(contentAsString, "$.access_token");

        JWTClaimsSet jwtClaimsSet = SignedJWT.parse(accessToken).getJWTClaimsSet();
        assertEquals("testClient", jwtClaimsSet.getClaim("client_id"));
        assertEquals(userName, jwtClaimsSet.getClaim("user_name"));

        String meContentAsString = mockMvc.perform(MockMvcRequestBuilders.get(ME_URL)
                .with(mockHttpServletRequest -> {
                    mockHttpServletRequest.addHeader(AUTHORIZATION_HEADER,
                            String.format("%s %s", BEARER_TOKEN_TYPE, accessToken));
                    return mockHttpServletRequest;
                })
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();


        Map<String, Object> meClaims = objectMapper.readValue(meContentAsString, new TypeReference<Map<String, Object>>() {
        });

        assertEquals(userName, meClaims.get("login"));
        Object roles = meClaims.get("roles");
        assertTrue(roles instanceof ArrayList);
        assertIterableEquals(Lists.newArrayList("ADMIN_CLIENT"), ((ArrayList) roles));

    }


}