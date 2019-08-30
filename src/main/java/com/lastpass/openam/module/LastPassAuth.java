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

import com.iplanet.sso.SSOException;
import com.lastpass.common.crypto.RSAUtils;
import com.lastpass.provisioning.UsersProvisioning;
import com.lastpass.provisioning.model.User;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.LoginException;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import java.io.ByteArrayInputStream;
import java.security.Principal;
import java.util.HashSet;
import java.util.Iterator;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import org.forgerock.openam.core.CoreWrapper;

public class LastPassAuth extends AMLoginModule {

    // Name for the debug-log
    private final static Debug DEBUG = Debug.getInstance("LastPassAuth");
    private String username;
    private String email;
    private String firstName;
    private String lastName;

    // Orders defined in the callbacks file
    private final static int STATE_BEGIN = 1;
    private final static int STATE_AUTH = 2;
    private final static int STATE_LOCAL_AUTH = 3;
    private final static int STATE_ERROR = 4;

    // Errors properties
    private final static String USER_NOT_FOUND = "error-user-not-found";
    private final static String USER_EMAIL_NOT_FOUND = "error-user-email-not-found";
    private final static String CONTACT_ADMINISTRATOR = "error-contact-admin";
    private final static String INVALID_USER = "error-invalid-user";
    private final static String ACCESS_DENIED = "error-access-denied";

    // LDAP directory attributes
    private static final String DN = "dn";
    private static final String GIVEN_NAME = "givenName";
    private static final String SN = "sn";
    private static final String EMAIL = "mail";
    private static final String USER_PPAL_NAME = "userPrincipal";

    private static final String RSA_PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String RSA_PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----";
    private static final String RSA_PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String RSA_PRIVATE_KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    private Map<String, Set<String>> options;
    private ResourceBundle bundle;
    private Map<String, String> sharedState;
    private String lastPassMFAKey;
    private String genericAPIKey;
    private String provisioningURL;
    private String amAuthModuleURL;
    private UsersProvisioning provisioning;
    private String authURL;

    public LastPassAuth() {
        super();
    }

    /**
     * This method stores service attributes and localized properties for later
     * use.
     *
     * @param subject
     * @param sharedState
     * @param options
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        DEBUG.message("LastPassAuth::init");
        this.options = options;
        this.sharedState = sharedState;
        this.bundle = amCache.getResBundle("amAuthLastPassAuth", getLoginLocale());
        this.lastPassMFAKey = CollectionHelper.getMapAttr(options, Constants.LASTPASS_MFA_KEY);
        this.genericAPIKey = CollectionHelper.getMapAttr(options, Constants.GENERIC_API_KEY);
        this.authURL = CollectionHelper.getMapAttr(options, Constants.AUTH_URL);
        this.provisioningURL = CollectionHelper.getMapAttr(options, Constants.PROVISIONING_URL);
        this.amAuthModuleURL = CollectionHelper.getMapAttr(options, Constants.AM_AUTH_MODULE_URL);

        DEBUG.message("provisioning URL = " + provisioningURL);
        DEBUG.message("auth module URL = " + amAuthModuleURL);

        String publicKey = formatRSAKey(
                CollectionHelper.getMapAttr(options, Constants.PUBLIC_KEY),
                RSA_PUBLIC_KEY_HEADER, RSA_PUBLIC_KEY_FOOTER);
        String privateKey = formatRSAKey(
                CollectionHelper.getMapAttr(options, Constants.PRIVATE_KEY),
                RSA_PRIVATE_KEY_HEADER, RSA_PRIVATE_KEY_FOOTER);

        if (publicKey != null && privateKey != null) {
            try {
                provisioning = new UsersProvisioning(
                        RSAUtils.loadPublicKey(new ByteArrayInputStream(publicKey.getBytes())),
                        RSAUtils.loadPrivateKey(new ByteArrayInputStream(privateKey.getBytes())),
                        this.genericAPIKey,
                        this.provisioningURL
                );
            } catch (Exception ex) {
                DEBUG.error("Error loading LastPass Module RSA keys", ex);
                throw new RuntimeException("Error loading LastPass Module RSA keys");
            }
        }
    }

    public String formatRSAKey(String key, String header, String footer) {
        if (key == null) {
            return null;
        }

        key = key.replace(header, "")
                .replace(footer, "")
                .replaceAll(" ", "\n");

        return String.format("%s%s%s", header, key, footer);
    }

    @Override
    public int process(Callback[] callbacks, int state) throws LoginException {
        DEBUG.message("LastPassAuth::process state: {}", state);

        switch (state) {
            case STATE_BEGIN:
                // modify the UI and proceed to next state
                substituteUIStrings();
                return STATE_AUTH;
            case STATE_AUTH:
                // Get data from callbacks. Refer to callbacks XML file.
                NameCallback nc = (NameCallback) callbacks[0];
                username = nc.getName();

                // validate user
                if (username == null || "".equals(username)) {
                    setErrorText(INVALID_USER);
                    return STATE_ERROR;
                }

                String realm = DNMapper.orgNameToRealmName(getRequestOrg());
                AMIdentity userIdentity = new CoreWrapper().getIdentity(username, realm);

                if (userIdentity == null) {
                    setErrorText(USER_NOT_FOUND);
                    return STATE_ERROR;
                }

                retrieveUserAttributes(userIdentity);

                if (email == null) {
                    setErrorText(USER_EMAIL_NOT_FOUND);
                    return STATE_ERROR;
                }

                // check if user exists in LastPass db
                try {
                    if (!userExists(email)) {
                        collectPassword();
                        return STATE_LOCAL_AUTH;
                    }
                } catch (Exception e) {
                    DEBUG.error("Error verifying if user " + username + " exists at LastPass", e);
                    setErrorText(CONTACT_ADMINISTRATOR);
                    return STATE_ERROR;
                }

                // if user exists, then authenticate with LastPass
                if (AuthHelper.authenticateUser(email, authURL, lastPassMFAKey)) {
                    storeUsername(username);
                    return ISAuthConstants.LOGIN_SUCCEED;
                } else {
                    setErrorText(ACCESS_DENIED);
                    return STATE_ERROR;
                }
            case STATE_LOCAL_AUTH:
                DEBUG.message(String.format("local authentication for {username=%s, FirstName=%s, LastName=%s, Email=%s}", username, firstName, lastName, email));
                PasswordCallback pwdCB = (PasswordCallback) callbacks[0];
                String password = new String(pwdCB.getPassword());

                // user doesn't exist in LastPass db, perform local auth
                if (AuthHelper.authenticateLocalUser(username, password, amAuthModuleURL)) {
                    DEBUG.message("provision the user to LastPass");
                    try {
                        // provision the user to LastPass
                        userProvisioning();
                        return ISAuthConstants.LOGIN_SUCCEED;
                    } catch (Exception e) {
                        DEBUG.error("Error provisioning user " + username + " to LastPass", e);
                        setErrorText(CONTACT_ADMINISTRATOR);
                        return STATE_ERROR;
                    }
                } else {
                    DEBUG.message("local authentication failed");
                    return STATE_ERROR;
                }
            case STATE_ERROR:
                return STATE_ERROR;
            default:
                throw new AuthLoginException("invalid state");
        }
    }

    @Override
    public Principal getPrincipal() {
        return new LastPassAuthPrincipal(username);
    }

    private boolean userExists(String email) throws Exception {
        return provisioning.isUserExists(email);
    }

    private void setErrorText(String err) throws AuthLoginException {
        // Receive correct string from properties and substitute the
        // header in callbacks order 3.
        substituteHeader(STATE_ERROR, bundle.getString(err));
    }

    public boolean userProvisioning() throws Exception {
        User user = new User(email, firstName, lastName);
        return provisioning.addUser(user);
    }

    private void collectPassword() throws AuthLoginException {
        substituteHeader(STATE_LOCAL_AUTH, bundle.getString(Constants.UI_REGISTER_HEADER));
        replaceCallback(STATE_LOCAL_AUTH, 0, new PasswordCallback(bundle.getString(Constants.UI_PASSWORD_PROMPT), false));
    }

    private void substituteUIStrings() throws AuthLoginException {
        substituteHeader(STATE_AUTH, bundle.getString(Constants.UI_LOGIN_HEADER));
        replaceCallback(STATE_AUTH, 0, new NameCallback(
                bundle.getString(Constants.UI_USERANAME_PROMPT)));
    }

    private void retrieveUserAttributes(AMIdentity userIdentity) throws AuthLoginException {
        DEBUG.message("retrieve user attributes - " + userIdentity.getName());
        try {
            Set<String> a = new HashSet<>();
            a.add(EMAIL);
            a.add(USER_PPAL_NAME);
            a.add(DN);
            a.add(SN);
            a.add(GIVEN_NAME);

            email = getAttribute(EMAIL, userIdentity);
            lastName = getAttribute(SN, userIdentity);
            firstName = getAttribute(GIVEN_NAME, userIdentity);

            //if both mail and email are empty, then get email from dn
            if (email == null) {
                String dn = getAttribute(DN, userIdentity);
                email = getEmailFromDN(dn);    //userIdentity.getDn() return null!!!
            }
        } catch (SSOException | IdRepoException ex) {
            DEBUG.message("An error ocurred when getting user email: " + username, ex);
            setErrorText(CONTACT_ADMINISTRATOR);
        }
    }

    private String getAttribute(String attr, AMIdentity userIdentity) throws IdRepoException, SSOException {
        Set<String> attrs = userIdentity.getAttribute(attr);
        Iterator<String> iterator = attrs.iterator();

        while (iterator.hasNext()) {
            return iterator.next();
        }
        return null;
    }

    private String getEmailFromDN(String dn) {
        if (dn == null || !dn.contains("dc=")) {
            return "";
        }

        String[] dc = dn.split(",dc=");
        int eqIdx = dn.indexOf('=');
        StringBuilder sb = new StringBuilder();
        sb.append(dn.substring(eqIdx + 1, dn.indexOf(',', eqIdx)))
                .append('@');

        for (int i = 1; i < dc.length; i++) {
            sb.append(dc[i]);

            if (i < dc.length - 1) {
                sb.append('.');
            }
        }
        return sb.toString();
    }

}
