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
package com.lastpass.openam.module;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.identity.shared.debug.Debug;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 *
 * @author LastPass
 */
public class AuthHelper {

    private final static Debug DEBUG = Debug.getInstance("AuthHelper");
    private static final Pattern API_KEY_REGEX = Pattern.compile("[a-z0-9-]{36,36}");

    /**
     * Pure JSE REST client
     *
     * @param <T>
     * @param url URL
     * @param o Data
     * @param headers
     * @param resultType Class
     * @return
     * @throws MalformedURLException
     * @throws IOException
     */
    public static <T> T doPost(String url, Object o, Map<String, String> headers, Class<T> resultType) throws MalformedURLException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        String payload = mapper.writeValueAsString(o);
        URL urlx = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) urlx.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");

        if (headers != null) {
            headers.forEach((k, v) -> {
                conn.setRequestProperty(k, v);
            });
        }

        OutputStream out = conn.getOutputStream();
        out.write(payload.getBytes());
        out.flush();
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new RuntimeException("Failed: HTTP error code " + conn.getResponseCode());
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        StringBuilder input = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            input.append(line);
        }
        conn.disconnect();
        return mapper.readValue(input.toString(), resultType);
    }

    public static boolean authenticateLocalUser(String username, String password, String authURL) {
        Map<String, String> headers = new HashMap();
        headers.put("X-OpenAM-Username", username);
        headers.put("X-OpenAM-Password", password);
        headers.put("Accept-API-Version", "resource=2.0, protocol=1.0");

        try {
            Map<String, Object> response = doPost(authURL, null, headers, Map.class);
            return response.containsKey("successUrl");
        } catch (IOException ex) {
            DEBUG.error("Error performing local authentication for user: " + username, ex);
            return false;
        }
    }

    public static boolean authenticateUser(String username, String authURL, String lastPassMFAKey) {
        try {
            Map request = makeAuthRequest(username, lastPassMFAKey);
            DEBUG.message(request.toString());
            Map<String, Object> response = doPost(authURL, request, null, Map.class);
            DEBUG.message(response.toString());

            if ((boolean) response.get(Constants.SUCCEEDED)) {
                String result = (String) ((Map) response.get(Constants.VALUE)).get(Constants.AUTH_STATUS);
                return Constants.SUCCESS.equals(result);
            } else {
                DEBUG.error(String.format("User authentication failed: %s", username, response.get(Constants.MESSAGE)));
            }
        } catch (IOException ex) {
            DEBUG.error("Error authenticating user: " + username, ex);
        } catch (IllegalArgumentException ex) {
            DEBUG.error("invalid authentication request", ex);
        }
        return false;
    }

    public static Map makeAuthRequest(String username, String apiKey) {
        if (!isValidUsername(username)) {
            DEBUG.message("Invalid user: " + username);
            throw new IllegalArgumentException("invalid user");
        }

        if (!isValidAPIKey(apiKey)) {
            throw new IllegalArgumentException("invalid API key");
        }

        Map<String, String> request = new HashMap();
        request.put(Constants.API_KEY, apiKey);
        request.put(Constants.USERNAME, username);
        request.put(Constants.DEVICE_NAME, "ForgeRock AM");
        return request;
    }

    public static boolean isValidUsername(String username) {
        if (username == null || username.length() < 3) {
            return false;
        }

        return username.indexOf('@') >= 1;
    }

    public static boolean isValidAPIKey(String apiKey) {
        return apiKey == null ? false : API_KEY_REGEX.matcher(apiKey).matches();
    }

}
