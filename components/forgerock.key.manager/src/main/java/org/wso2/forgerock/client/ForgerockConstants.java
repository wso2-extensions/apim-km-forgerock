/*
/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.forgerock.client;

/**
 * This class will hold constants related to Okta key manager implementation.
 */
public class ForgerockConstants {
    public static final String UTF_8 = "UTF-8";
    public static final String HTTP_HEADER_CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json";
    public static final String AUTHORIZATION = "Authorization";
    public static final String ACCESS_TOKEN = "accessToken";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String AUTHENTICATION_BASIC = "Basic ";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String ACCESS_TOKEN_SCOPE = "scope";
    public static final String CLIENT_REDIRECT_URIS = "redirect_uris";
    public static final String CLIENT_GRANT_TYPES = "grant_types";
    public static final String CLIENT_NAME = "client_name";
    public static final String REGISTRATION_ACCESS_TOKEN = "registration_access_token";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    public static final String CLIENT_APPLICATION_TYPE = "application_type";
    public static final String CLIENT_ACCESS_TOKEN_LIFETIME = "access_token_lifetime";
    public static final String CLIENT_REFRESH_TOKEN_LIFETIME = "refresh_token_lifetime";
    public static final String CLIENT_AUTH_CODE_LIFETIME = "authorization_code_lifetime";
    public static final String CLIENT_RESPONSE_TYPES = "response_types";
    public static final String CLIENT_URI = "client_uri";
    public static final String ACCESS_TOKEN_AUDIENCE = "aud";
    public static final String ACCESS_TOKEN_ISSUER = "iss";
    public static final String ACCESS_TOKEN_TYPE = "token_type";
    public static final String ACCESS_TOKEN_SUBJECT = "sub";
    public static final String ACCESS_TOKEN_USER_ID = "uid";
    public static final String ACCESS_TOKEN_IDENTIFIER = "jti";
    public static final String FORGEROCK_DEFAULT_SCOPE = "defaultScope";
    public static final String DEFAULT_SCOPE = "default";
    public static final String TOKEN_SCOPE = "tokenScope";
    public static final String TOKEN_GRANT_TYPE = "tokenGrantType";
    public static final String ERROR_ENCODING_METHOD_NOT_SUPPORTED = "Encoding method is not supported";
    public static final String ERROR_COULD_NOT_READ_HTTP_ENTITY = "Could not read http entity for response";
    public static final String STRING_FORMAT = "%s %s";
    public static final String ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER = "Error has occurred while reading " +
            "or closing buffer reader";
    public static final String REQUEST_OBJECT_SIGNING_ALGORITHM = "request_object_signing_alg";
    public static final String JWKS = "jwks";
    public static final String SCOPE = "scp";
    public static final String APP_UNFO = "APP_INFO";
    public static final String AUD = "aud";
    public static final String DEFAULT_CALLBACK = "https://localhost:9443";
    public static final String KM_TYPE = "Forgerock";
    ForgerockConstants() {
    }
}
