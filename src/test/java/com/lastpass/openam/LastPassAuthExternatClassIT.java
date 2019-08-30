/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2011-2017 ForgeRock AS. All Rights Reserved
 */
/**
 * Portions Copyright 2018 LastPass
 */
package com.lastpass.openam;

import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 *
 * @author LastPass
 */
public class LastPassAuthExternatClassIT {

    private static final String AM_AUTHENTICATE_ENDPOINT
            = "http://ec2-35-165-249-211.us-west-2.compute.amazonaws.com:8080/openam/json/realms/root/authenticate?module=LastPass&authIndexType=module&authIndexValue=LastPass";

    @Test
    public void testFail() throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        //Get Initial Auth ID
        ResponseEntity<LastPassAuthCallback> entity
                = restTemplate.exchange(AM_AUTHENTICATE_ENDPOINT,
                        HttpMethod.POST,
                        new HttpEntity<>(httpHeaders),
                        LastPassAuthCallback.class);
        LastPassAuthCallback callback = entity.getBody();

        //Set incorrect username
        callback.setUsername("notexists");
        System.out.println(callback);

        //Authenticate to OpenAM
        try {
            restTemplate.exchange(AM_AUTHENTICATE_ENDPOINT,
                    HttpMethod.POST, new HttpEntity<>(callback, httpHeaders), String.class);
        } catch (HttpClientErrorException e) {
            //Assert response is 401
            Assert.assertEquals(e.getStatusCode(), HttpStatus.UNAUTHORIZED);
            return;
        }
        // Fail if 401 isn't received
        Assert.fail();
    }
}
