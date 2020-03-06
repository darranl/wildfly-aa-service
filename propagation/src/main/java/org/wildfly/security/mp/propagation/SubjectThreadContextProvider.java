/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mp.propagation;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.function.Supplier;

import javax.security.auth.Subject;

import org.eclipse.microprofile.context.spi.ThreadContextController;
import org.eclipse.microprofile.context.spi.ThreadContextProvider;
import org.eclipse.microprofile.context.spi.ThreadContextSnapshot;
import org.kohsuke.MetaInfServices;

import io.smallrye.context.spi.WrappingThreadContextSnapshot;

/**
 * A {@code ThreadContextProvider} implementation to propagate a {@link Subject}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MetaInfServices(ThreadContextProvider.class)
public class SubjectThreadContextProvider implements ThreadContextProvider {

    static final String TYPE = "Subject";

    @Override
    public ThreadContextSnapshot currentContext(Map<String, String> props) {
        return new SubjectThreadContextSnapshot(Subject.getSubject(AccessController.getContext()));
    }

    @Override
    public ThreadContextSnapshot clearedContext(Map<String, String> props) {
        return new SubjectThreadContextSnapshot(null);
    }

    @Override
    public String getThreadContextType() {
        return TYPE;
    }

    static class SubjectThreadContextSnapshot implements WrappingThreadContextSnapshot {

        private final Subject subject;

        SubjectThreadContextSnapshot(final Subject subject) {
            this.subject = subject;
        }

        @Override
        public ThreadContextController begin() {
            return () -> {};
        }

        @Override
        public boolean needsToWrap() {
            return true;
        }

        @Override
        public <T> Supplier<T> wrap(Supplier<T> task) {
            return () -> Subject.doAs(subject, (PrivilegedAction<T>) task::get);
        }

    }

}
