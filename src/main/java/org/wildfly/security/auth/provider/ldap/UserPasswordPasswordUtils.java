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
import java.security.spec.InvalidKeySpecException;

import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;

/**
 * A password utility for LDAP formatted passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordPasswordUtils {

    static final Charset UTF_8 = Charset.forName("UTF-8");

    private UserPasswordPasswordUtils() {
    }

    public static PasswordSpec parseUserPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword == null || userPassword.length == 0) {
            throw new IllegalArgumentException("userPassword can not be null or empty.");
        }

        if (userPassword[0] != '{') {
            return createClearPasswordSpec(userPassword);
        }

        return null;
    }

    private static PasswordSpec createClearPasswordSpec(byte[] userPassword) {
        return new ClearPasswordSpec(new String(userPassword, UTF_8).toCharArray());
    }

}
