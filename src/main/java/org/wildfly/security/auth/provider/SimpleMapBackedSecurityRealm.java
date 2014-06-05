/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.auth.provider;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.wildfly.security.auth.SecurityIdentity;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.util.NameRewriter;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.password.Password;

/**
 * Simple map-backed security realm.  Uses an in-memory copy-on-write map methodology to map user names to
 * passwords.  Since this security realm implementation holds all names in memory, it may not be the best choice
 * for very large security realms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class SimpleMapBackedSecurityRealm implements SecurityRealm {
    private final NameRewriter[] rewriters;
    private volatile Map<NamePrincipal, Password> map = Collections.emptyMap();

    public SimpleMapBackedSecurityRealm(final NameRewriter... rewriters) {
        this.rewriters = rewriters.clone();
    }

    /**
     * Set the password map.  Note that the password map must <b>not</b> be modified after calling this method.
     * If it needs to be changed, pass in a new map that is a copy of the old map with the required changes.
     *
     * @param passwordMap the password map
     */
    public void setPasswordMap(final Map<NamePrincipal, Password> passwordMap) {
        map = passwordMap;
    }

    public Principal mapNameToPrincipal(String name) {
        for (NameRewriter rewriter : rewriters) {
            name = rewriter.rewriteName(name);
        }
        return new NamePrincipal(name);
    }

    public <C> C getCredential(final Class<C> credentialType, final Principal principal) {
        final Password password = map.get(principal);
        return credentialType.isInstance(password) ? credentialType.cast(password) : null;
    }

    private boolean checkType(final Set<Class<?>> supportedTypes, HashSet<Class<?>> checked, Class<?> actualType) {
        return actualType != null && checked.add(actualType) && (supportedTypes.contains(actualType) || checkType(supportedTypes, checked, actualType.getSuperclass()) || checkInterfaces(supportedTypes, checked, actualType));
    }

    private boolean checkInterfaces(final Set<Class<?>> supportedTypes, HashSet<Class<?>> checked, final Class<?> actualType) {
        for (Class<?> clazz : actualType.getInterfaces()) {
            if (checkType(supportedTypes, checked, clazz)) return true;
        }
        return false;
    }

    public CredentialSupport getCredentialSupport(final Class<?> credentialType) {
        return Password.class.isAssignableFrom(credentialType) ? CredentialSupport.POSSIBLY_SUPPORTED : CredentialSupport.UNSUPPORTED;
    }

    public CredentialSupport getCredentialSupport(final Principal principal, final Class<?> credentialType) {
        final Password password = map.get(principal);
        return credentialType.isInstance(password) ? CredentialSupport.SUPPORTED : CredentialSupport.UNSUPPORTED;
    }

    public <P> P proveAuthentic(final Principal principal, final Verifier<P> verifier) throws AuthenticationException {
        final Password password = map.get(principal);
        if (password != null) {
            Class<?> clazz = password.getClass();
            if (! checkType(verifier.getSupportedCredentialTypes(), new HashSet<Class<?>>(), clazz)) {
                throw new AuthenticationException("Unsupported credential type");
            }
            return verifier.performVerification(password);
        } else {
            throw new AuthenticationException("No such user");
        }
    }

    public SecurityIdentity createSecurityIdentity(final Principal principal) {
        return null;
    }
}
