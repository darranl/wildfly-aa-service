/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider.ldap;

import java.util.Map;

import org.wildfly.security.auth.provider.CredentialSupport;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UserPasswordCredentialLoader implements CredentialLoader {

    static final String DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME = "userPassword";

    private final String userPasswordAttributeName;
    private final Map<Class<?>, CredentialSupport> credentialSupportMap;

    public UserPasswordCredentialLoader(String userPasswordAttributeName, Map<Class<?>, CredentialSupport> credentialSupportMap) {
        this.userPasswordAttributeName = userPasswordAttributeName;
        this.credentialSupportMap = credentialSupportMap;
    }

    @Override
    public CredentialSupport getCredentialSupport(DirContextFactory contextFactory, Class<?> credentialType) {
        if (credentialSupportMap.isEmpty()) {
            return CredentialSupport.POSSIBLY_SUPPORTED;
        }
        CredentialSupport response = credentialSupportMap.get(credentialType);
        if (response == null) {
            response = CredentialSupport.UNSUPPORTED;
        }

        return response;
    }

}
