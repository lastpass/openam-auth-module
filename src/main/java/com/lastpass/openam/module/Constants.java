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

/**
 *
 * @author LastPass
 */
public class Constants {

    //i18n properties
    public static final String UI_LOGIN_HEADER = "ui-login-header";
    public static final String UI_REGISTER_HEADER = "ui-register-header";
    public static final String UI_USERANAME_PROMPT = "ui-username-prompt";
    public static final String UI_PASSWORD_PROMPT = "ui-password-prompt";

    //Authentication request attributes
    public static final String USERNAME = "Username";
    public static final String COMMAND = "Command";
    public static final String API_KEY = "APIKey";
    public static final String USER_STATUS = "UserStatus";
    public static final String DEVICE_NAME = "DeviceName";

    //Authentication result attributes
    public static final String AUTH_STATUS = "AuthStatus";
    public static final String SUCCESS = "Success";
    public static final String SUCCEEDED = "Succeeded";
    public static final String MESSAGE = "Message";
    public static final String VALUE = "Value";

    //config properties
    public static final String AUTH_URL = "authUrl";
    public static final String PROVISIONING_URL = "provisioningUrl";
    public static final String AM_AUTH_MODULE_URL = "authModuleUrl";
    public static final String LASTPASS_MFA_KEY = "lastPassMFAKey";
    public static final String GENERIC_API_KEY = "genericAPIKey";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";
    public static final String EMAIL_DOMAIN = "emailDomain";

}
