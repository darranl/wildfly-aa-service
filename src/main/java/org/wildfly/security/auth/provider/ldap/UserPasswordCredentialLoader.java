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

import java.nio.charset.Charset;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.verifier.Verifier;

/**
 * A {@link CredentialLoader} for loading credentials stored within the 'userPassword' attribute of LDAP entries.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordCredentialLoader implements CredentialLoader {

    private static final Charset UTF_8 = Charset.forName("UTF-8");

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

    @Override
    public IdentityCredentialLoader forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }



    private class ForIdentityLoader implements IdentityCredentialLoader {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) {
            DirContext context = null;
            try {
                context =  contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName, new String[] { userPasswordAttributeName });
                Attribute attribute = attributes.get(userPasswordAttributeName);
                for (int i = 0; i < attribute.size(); i++) {
                    Object attributeValue = attribute.get(i);
                    String value;
                    if (attributeValue instanceof byte[]) {
                        value = new String((byte[]) attributeValue, UTF_8);
                    } else {
                        value = attributeValue.toString();
                    }
                    System.out.println(value);
                }

                return null;
            } catch (NamingException e) {
                return CredentialSupport.UNSUPPORTED;
            } finally {
                contextFactory.returnContext(context);
            }
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public <P> P proveAuthentic(Verifier<P> verifier) throws AuthenticationException {
            // TODO Auto-generated method stub
            return null;
        }



    }

}
