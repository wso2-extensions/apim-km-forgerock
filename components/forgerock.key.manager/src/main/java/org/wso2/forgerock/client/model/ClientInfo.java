/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.forgerock.client.model;

import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

public class ClientInfo {

    @SerializedName("client_id")
    private String clientId;
    @SerializedName("application_type")
    private String applicationType;
    @SerializedName("client_name#en")
    private String clientName;
    @SerializedName("client_secret")
    private String clientSecret;
    @SerializedName("client_type")
    private String clientType;
    @SerializedName("client_secret_expires_at")
    private Long clientSecretExpiredTime;
    @SerializedName("access_token_lifetime")
    private Long accessTokenLifeTime;
    @SerializedName("refresh_token_lifetime")
    private Long refreshTokenLifeTime;
    @SerializedName("authorization_code_lifetime")
    private Long authCodeLifeTime;
    @SerializedName("redirect_uris")
    private List<String> redirectUris = new ArrayList<>();
    @SerializedName("default_scopes")
    private List<String> defaultScopes = new ArrayList<>();
    @SerializedName("registration_client_uri")
    private String clientUri;
    @SerializedName("response_types")
    private List<String> responseTypes = new ArrayList<>();
    @SerializedName("token_endpoint_auth_method")
    private String tokenEndpointAuthMethod;
    @SerializedName("request_object_signing_alg")
    private String requestObjectSigningAlgorithm;
    @SerializedName("jwks")
    private JWKS jwks;
    @SerializedName("grant_types")
    private List<String> grantTypes = new ArrayList<>();
    @SerializedName("registration_access_token")
    private String registrationAccessToken;

    public String getRegistrationAccessToken() {

        return registrationAccessToken;
    }

    public void setRegistrationAccessToken(String registrationAccessToken) {

        this.registrationAccessToken = registrationAccessToken;
    }

    public List<String> getDefaultScopes() {

        return defaultScopes;
    }

    public void setDefaultScopes(List<String> defaultScopes) {

        this.defaultScopes = defaultScopes;
    }

    public List<String> getGrantTypes() {

        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {

        this.grantTypes = grantTypes;
    }

    public String getClientId() {

        return clientId;
    }

    public void setClientId(String clientId) {

        this.clientId = clientId;
    }

    public String getApplicationType() {

        return applicationType;
    }

    public void setApplicationType(String applicationType) {

        this.applicationType = applicationType;
    }

    public String getClientName() {

        return clientName;
    }

    public void setClientName(String clientName) {

        this.clientName = clientName;
    }

    public String getClientSecret() {

        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {

        this.clientSecret = clientSecret;
    }

    public Long getClientSecretExpiredTime() {

        return clientSecretExpiredTime;
    }

    public void setClientSecretExpiredTime(Long clientSecretExpiredTime) {

        this.clientSecretExpiredTime = clientSecretExpiredTime;
    }

    public List<String> getRedirectUris() {

        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {

        this.redirectUris = redirectUris;
    }

    public List<String> getResponseTypes() {

        return responseTypes;
    }

    public String getClientType() {

        return clientType;
    }

    public void setClientType(String clientType) {

        this.clientType = clientType;
    }

    public Long getAccessTokenLifeTime() {

        return accessTokenLifeTime;
    }

    public void setAccessTokenLifeTime(Long accessTokenLifeTime) {

        this.accessTokenLifeTime = accessTokenLifeTime;
    }

    public Long getRefreshTokenLifeTime() {

        return refreshTokenLifeTime;
    }

    public void setRefreshTokenLifeTime(Long refreshTokenLifeTime) {

        this.refreshTokenLifeTime = refreshTokenLifeTime;
    }

    public String getClientUri() {

        return clientUri;
    }

    public void setClientUri(String clientUri) {

        this.clientUri = clientUri;
    }

    public void setResponseTypes(List<String> responseTypes) {

        this.responseTypes = responseTypes;
    }

    public String getTokenEndpointAuthMethod() {

        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {

        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getRequestObjectSigningAlgorithm() {

        return requestObjectSigningAlgorithm;
    }

    public void setRequestObjectSigningAlgorithm(String requestObjectSigningAlgorithm) {

        this.requestObjectSigningAlgorithm = requestObjectSigningAlgorithm;
    }

    public JWKS getJwks() {

        return jwks;
    }

    public void setJwks(JWKS jwks) {

        this.jwks = jwks;
    }

    public Long getAuthCodeLifeTime() {

        return authCodeLifeTime;
    }

    public void setAuthCodeLifeTime(Long authCodeLifeTime) {

        this.authCodeLifeTime = authCodeLifeTime;
    }
}
