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

import java.io.Serializable;
import java.security.Principal;

public class LastPassAuthPrincipal implements Principal, Serializable {

    private final String name;

    public LastPassAuthPrincipal(String name) {

        if (name == null) {
            throw new NullPointerException("illegal null input");
        }

        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "LastPassAuthPrincipal{" + "name=" + name + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (this == o) {
            return true;
        }

        if (!(o instanceof LastPassAuthPrincipal)) {
            return false;
        }
        LastPassAuthPrincipal that = (LastPassAuthPrincipal) o;

        return this.getName().equals(that.getName());
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}
