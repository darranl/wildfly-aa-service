/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import static java.security.AccessController.doPrivileged;

import java.net.URI;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import org.wildfly.common.context.ContextManager;
import org.wildfly.common.context.Contextual;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.ParametricPrivilegedExceptionAction;
import org.wildfly.security.Version;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContext implements Contextual<AuthenticationContext> {

    private static final ContextManager<AuthenticationContext> CONTEXT_MANAGER = new ContextManager<AuthenticationContext>(AuthenticationContext.class);

    private static final Supplier<AuthenticationContext> SUPPLIER = doPrivileged((PrivilegedAction<Supplier<AuthenticationContext>>) CONTEXT_MANAGER::getPrivilegedSupplier);

    static {
        Version.getVersion();
        CONTEXT_MANAGER.setGlobalDefaultSupplier(() -> DefaultAuthenticationContextProvider.DEFAULT);
    }

    private final RuleConfigurationPair[] rules;
    private final UnaryOperator<AuthenticationConfiguration> configurationOperator;

    private static final RuleConfigurationPair[] NO_RULES = new RuleConfigurationPair[0];

    static final AuthenticationContext EMPTY = new AuthenticationContext();

    private AuthenticationContext() {
        this(NO_RULES, false, (ac) -> ac);
    }

    AuthenticationContext(final RuleConfigurationPair[] rules, boolean clone, final UnaryOperator<AuthenticationConfiguration> configurationOperator) {
        if (clone) {
            this.rules = rules.clone();
        } else {
            this.rules = rules;
        }
        this.configurationOperator = configurationOperator;
    }

    /**
     * Get a new, empty authentication context.
     *
     * @return the new authentication context
     */
    public static AuthenticationContext empty() {
        return EMPTY;
    }

    /**
     * Get the current thread's captured authentication context.
     *
     * @return the current thread's captured authentication context
     */
    public static AuthenticationContext captureCurrent() {
        return SUPPLIER.get();
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the given rule and configuration at
     * the end of its list.
     *
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined authentication context
     */
    public AuthenticationContext with(MatchRule rule, AuthenticationConfiguration configuration) {
        if (configuration == null || rule == null) return this;
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (length == 0) {
            return new AuthenticationContext(new RuleConfigurationPair[] { new RuleConfigurationPair(rule, configuration) }, false, configurationOperator);
        } else {
            final RuleConfigurationPair[] copy = Arrays.copyOf(rules, length + 1);
            copy[length] = new RuleConfigurationPair(rule, configuration);
            return new AuthenticationContext(copy, false, configurationOperator);
        }
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the rules and configurations of the
     * given context at the end of its list.
     *
     * @param other the other authentication context
     * @return the combined authentication context
     */
    public AuthenticationContext with(AuthenticationContext other) {
        if (other == null) return this;
        final RuleConfigurationPair[] rules = this.rules;
        final RuleConfigurationPair[] otherRules = other.rules;
        final int length = rules.length;
        final int otherLength = otherRules.length;
        if (length == 0) {
            return other;
        } else if (otherLength == 0) {
            return this;
        }
        final RuleConfigurationPair[] copy = Arrays.copyOf(rules, length + otherLength);
        System.arraycopy(otherRules, 0, copy, length, otherLength);
        return new AuthenticationContext(copy, false, configurationOperator);
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the given rule and configuration
     * inserted at the position of its list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext with(int idx, MatchRule rule, AuthenticationConfiguration configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx > length) {
            throw new IndexOutOfBoundsException();
        }
        if (length == 0) {
            return new AuthenticationContext(new RuleConfigurationPair[] { new RuleConfigurationPair(rule, configuration) }, false, configurationOperator);
        } else {
            final RuleConfigurationPair[] copy = Arrays.copyOf(rules, length + 1);
            System.arraycopy(copy, idx, copy, idx + 1, length - idx);
            copy[idx] = new RuleConfigurationPair(rule, configuration);
            return new AuthenticationContext(copy, false, configurationOperator);
        }
    }

    /**
     * Get a new authentication context which is the same as this one, but which replaces the rule and configuration at the given
     * index with the given rule and configuration.
     *
     * @param idx the index at which insertion should be done
     * @param rule the rule to match
     * @param configuration the configuration to select when the rule matches
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext replacing(int idx, MatchRule rule, AuthenticationConfiguration configuration) throws IndexOutOfBoundsException {
        if (configuration == null || rule == null) return this;
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx > length) {
            throw new IndexOutOfBoundsException();
        }
        final RuleConfigurationPair[] copy = rules.clone();
        copy[idx] = new RuleConfigurationPair(rule, configuration);
        return new AuthenticationContext(copy, false, configurationOperator);
    }

    /**
     * Get a new authentication context which is the same as this one, but which includes the rules and configurations of the
     * given context inserted at the position of this context's list indicated by the {@code idx} parameter.
     *
     * @param idx the index at which insertion should be done
     * @param other the other authentication context
     * @return the combined authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext with(int idx, AuthenticationContext other) throws IndexOutOfBoundsException {
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (idx == length) return with(other);
        if (idx == 0) return other.with(this);
        if (idx < 0 || idx > length) {
            throw new IndexOutOfBoundsException();
        }
        if (other == null) return this;
        final RuleConfigurationPair[] otherRules = other.rules;
        final int otherLength = otherRules.length;
        if (otherLength == 0) return this;
        if (length == 0) {
            return other;
        } else {
            final RuleConfigurationPair[] copy = Arrays.copyOf(rules, length + otherLength);
            System.arraycopy(copy, idx, copy, idx + otherLength, length - idx);
            System.arraycopy(otherRules, 0, copy, idx, otherLength);
            return new AuthenticationContext(copy, false, configurationOperator);
        }
    }

    /**
     * Get a new authentication context which is the same as this one, but without the rule and configuration at the index
     * indicated by the {@code idx} parameter.
     *
     * @param idx the index at which removal should be done
     * @return the modified authentication context
     * @throws IndexOutOfBoundsException if the index is out of bounds
     */
    public AuthenticationContext without(int idx) throws IndexOutOfBoundsException {
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx >= length) {
            throw new IndexOutOfBoundsException();
        }
        if (length == 1) {
            assert idx == 0;
            return EMPTY;
        }
        final RuleConfigurationPair[] copy;
        if (idx == 0) {
            copy = Arrays.copyOfRange(rules, 1, length - 1);
        } else if (idx == length - 1) {
            copy = Arrays.copyOfRange(rules, 0, length - 1);
        } else {
            copy = Arrays.copyOfRange(rules, 0, length - 1);
            System.arraycopy(rules, idx + 1, copy, idx, length - idx - 1);
        }
        return new AuthenticationContext(copy, false, configurationOperator);
    }

    public AuthenticationContext with(final UnaryOperator<AuthenticationConfiguration> configurationOperator) {
        UnaryOperator<AuthenticationConfiguration> combined = (ac) -> configurationOperator.apply(this.configurationOperator.apply(ac));
        return new AuthenticationContext(rules, true, combined);
    }

    int ruleMatching(URI uri) {
        for (int i = 0, rulesLength = rules.length; i < rulesLength; i++) {
            if (rules[i].getMatchRule().matches(uri)) return i;
        }
        return -1;
    }

    MatchRule getMatchRule(int idx) {
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx >= length) {
            throw new IndexOutOfBoundsException();
        }
        return rules[idx].getMatchRule();
    }

    AuthenticationConfiguration getAuthenticationConfiguration(int idx) {
        final RuleConfigurationPair[] rules = this.rules;
        final int length = rules.length;
        if (idx < 0 || idx >= length) {
            throw new IndexOutOfBoundsException();
        }
        return configurationOperator.apply(rules[idx].getConfiguration());
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     */
    public <T> T run(PrivilegedAction<T> action) {
        return runAction(action);
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param action the action to run under association
     * @param <T> the action return type
     * @return the action return value
     * @throws PrivilegedActionException if the action throws an exception
     */
    public <T> T run(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        return runExceptionAction(action);
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run under association
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action return value
     */
    public <T, P> T run(P parameter, ParametricPrivilegedAction<T, P> action) {
        return runFunction(action, parameter);
    }

    /**
     * Run a privileged action with this authentication context associated for the duration of the task.
     *
     * @param parameter the parameter to pass to the action
     * @param action the action to run under association
     * @param <T> the action return type
     * @param <P> the action parameter type
     * @return the action return value
     * @throws PrivilegedActionException if the action throws an exception
     */
    public <T, P> T run(P parameter, ParametricPrivilegedExceptionAction<T, P> action) throws PrivilegedActionException {
        try {
            return runExFunction(action, parameter);
        } catch (Exception e) {
            throw new PrivilegedActionException(e);
        }
    }

    public ContextManager<AuthenticationContext> getInstanceContextManager() {
        return getContextManager();
    }

    /**
     * Get the context manager for authentication contexts.
     *
     * @return the context manager for authentication contexts (not {@code null})
     */
    public static ContextManager<AuthenticationContext> getContextManager() {
        return CONTEXT_MANAGER;
    }
}
