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

package org.wildfly.security.auth.util;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * A simple mapping regular expression-based realm mapper.  The pattern is used to find the realm portion
 * of the user name.  Then, a map is consulted to map this realm portion to an actual configured realm name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class MappedRegexRealmMapper extends SimpleRegexRealmMapper {
    private final Map<String, String> realmNameMap;

    /**
     * Construct a new instance.
     *
     * @param realmNamePattern the realm portion pattern
     * @param realmNameMap the realm portion to realm name map
     */
    public MappedRegexRealmMapper(final Pattern realmNamePattern, final Map<String, String> realmNameMap) {
        super(realmNamePattern);
        this.realmNameMap = realmNameMap;
    }

    public String getRealmMapping(final String userName) {
        final String mappedRealmPart = super.getRealmMapping(userName);
        if (mappedRealmPart == null) return null;
        return realmNameMap.get(mappedRealmPart);
    }
}
