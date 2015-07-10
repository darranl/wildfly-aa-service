/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.http.impl;

import static org.wildfly.security.http.HttpConstants.BASIC;

import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.spi.ServerAuthenticationPolicy;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ServerMechanismFactoryImpl implements HttpServerAuthenticationMechanismFactory {

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#getMechanismNames(java.util.Map)
     */
    @Override
    public String[] getMechanismNames(Map<String, ?> properties) {
        ArrayList<String> mechanismNames = new ArrayList<>();

        if (isBasicSupported(properties)) {
            mechanismNames.add(BASIC);
        }

        return mechanismNames.toArray(new String[mechanismNames.size()]);
    }

    /**
     * @see org.wildfly.security.http.HttpServerAuthenticationMechanismFactory#createAuthenticationMechanism(java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler) {
        switch (mechanismName) {
            case BASIC:
                if (isBasicSupported(properties)) {
                    // TODO - Complete BASIC authentication configuration.
                    return new BasicAuthenticationMechanism(callbackHandler, "Elytron Realm", false);
                }
                break;
        }
        return null;
    }

    private boolean isBasicSupported(Map<String, ?> properties) {
        // TODO - Mechanism selection will also need policy to decide if mechanisms must be supported.
        ServerAuthenticationPolicy policy = getServerAuthenticationPolicy(properties);
        if (policy != null) {
            CredentialSupport plainSupport = policy.getCredentialSupport(ClearPassword.class);
            return plainSupport.isDefinitelyVerifiable() || plainSupport.mayBeVerifiable();
        }

        return true;
    }

    private ServerAuthenticationPolicy getServerAuthenticationPolicy(Map<String, ?> properties) {
        Object policy = properties.get(ServerAuthenticationPolicy.class.getName());
        if (policy != null && policy instanceof ServerAuthenticationPolicy) {
            return (ServerAuthenticationPolicy) policy;
        }
        return null;

    }

}
