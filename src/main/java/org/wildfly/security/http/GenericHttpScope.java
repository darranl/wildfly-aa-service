/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http;

import java.io.InputStream;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * A generic {@link HttpScope} implementation that is backed by a set of functions.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GenericHttpScope implements HttpScope {

    private final Supplier<String> id;
    private final BiConsumer<String, Object> setAttachment;
    private final Function<String, Object> getAttachment;
    private final BooleanSupplier invalidator;
    private final Function<String, InputStream> getResource;

    private GenericHttpScope(Builder builder) {
        this.id = builder.id;
        this.setAttachment = builder.setAttachment;
        this.getAttachment = builder.getAttachment;
        this.invalidator = builder.invalidator;
        this.getResource = builder.getResource;
    }

    @Override
    public String getID() {
        return id != null ? id.get() : null;
    }

    @Override
    public boolean supportsAttachments() {
        return setAttachment != null && getAttachment != null;
    }

    @Override
    public void setAttachment(String key, Object value) {
        if (setAttachment != null) {
            setAttachment.accept(key, value);
        }
    }

    @Override
    public Object getAttachment(String key) {
        return getAttachment != null ? getAttachment(key) : null;
    }

    @Override
    public boolean supportsInvalidation() {
        return invalidator != null;
    }

    @Override
    public boolean invalidate() {
        return invalidator != null ? invalidator.getAsBoolean() : false;
    }

    @Override
    public boolean supportsResources() {
        return getResource != null;
    }

    @Override
    public InputStream getResource(String path) {
        return getResource != null ? getResource.apply(path) : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Supplier<String> id;
        private BiConsumer<String, Object> setAttachment;
        private Function<String, Object> getAttachment;
        private BooleanSupplier invalidator;
        private Function<String, InputStream> getResource;

        Builder() {
        }

        /**
         * Sets the {@link Supplier<String>} that can supply the ID of this HttpScope.
         *
         * @param id the {@link Supplier<String>} that can supply the ID of this HttpScope.
         * @return {@code this} so that calls can be chained.
         */
        public Builder setId(Supplier<String> id) {
            this.id = id;

            return this;
        }

        /**
         * Set the {@link BiConsumer<String, Object>} function that can be used to set attachments.
         *
         * @param setAttachment the {@link BiConsumer<String, Object>} function that can be used to set attachments.
         * @return {@code this} so that calls can be chained.
         */
        public Builder setSetAttachment(BiConsumer<String, Object> setAttachment) {
            this.setAttachment = setAttachment;

            return this;
        }

        /**
         * Set the {@link Function<Object, String>} function that can be used to get attachments.
         *
         * @param getAttachment the {@link Function<Object, String>} function that can be used to get attachments.
         * @return {@code this} so that calls can be chained.
         */
        public Builder setGetAttachment(Function<String, Object> getAttachment) {
            this.getAttachment = getAttachment;

            return this;
        }

        /**
         * Set the {@link BooleanSupplier} function that can be used to invalidate this HttpScope.
         *
         * @param invalidator the {@link BooleanSupplier} function that can be used to invalidate this HttpScope.
         * @return {@code this} so that calls can be chained.
         */
        public Builder setInvalidator(BooleanSupplier invalidator) {
            this.invalidator = invalidator;

            return this;
        }

        /**
         * Set the {@link Function<String, InputStream>} function that can be used to obtain resources.
         *
         * @param getResource the {@link Function<String, InputStream>} function that can be used to obtain resources.
         * @return @return {@code this} so that calls can be chained.
         */
        public Builder setGetResource(Function<String, InputStream> getResource) {
            this.getResource = getResource;

            return this;
        }

        public HttpScope build() {
            return new GenericHttpScope(this);
        }
    }
}
