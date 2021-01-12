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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import feign.Feign;
import feign.auth.BasicAuthRequestInterceptor;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.okhttp.OkHttpClient;
import feign.slf4j.Slf4jLogger;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.*;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.ErrorItem;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.dao.ApiMgtDAO;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.forgerock.client.dao.ForgerockApiMgtDAO;
import org.wso2.forgerock.client.model.*;
import org.wso2.forgerock.client.model.ForgerockDCRClient;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * This class provides the implementation to use "Forgerock" for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class ForgerockOAuthClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(ForgerockOAuthClient.class);
    private ForgerockDCRClient forgeDCRClient;
    private IntrospectClient introspectClient;
    ForgerockApiMgtDAO apiMgtDAO = ForgerockApiMgtDAO.getInstance();
    String clientRegistrationEndpoint = null;
    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param keyManagerConfiguration Configuration as a {@link KeyManagerConfiguration}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {

        this.configuration = keyManagerConfiguration;
        clientRegistrationEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.CLIENT_REGISTRATION_ENDPOINT);
        String introspectEndpoint =
                (String) configuration.getParameter(APIConstants.KeyManager.INTROSPECTION_ENDPOINT);
        String clientId = (String) configuration.getParameter(ForgerockConstants.CLIENT_ID);
        String clientSecret = (String) configuration.getParameter(ForgerockConstants.CLIENT_SECRET);
        introspectClient =
                Feign.builder().client(new OkHttpClient()).encoder(new GsonEncoder()).decoder(new GsonDecoder())
                        .logger(new Slf4jLogger())
                        .requestInterceptor(new BasicAuthRequestInterceptor(clientId, clientSecret))
                        .encoder(new FormEncoder()).target(IntrospectClient.class, introspectEndpoint);
    }

    /**
     * This method will Register an OAuth client in Forgerock Authorization Server.
     *
     * @param oAuthAppRequest This object holds all parameters required to register an OAuth client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
        String accessToken = getRegistrationAccessToken();
        ForgerockDCRClient forgeDCRClient =
                Feign.builder().client(new OkHttpClient()).encoder(new GsonEncoder()).decoder(new GsonDecoder())
                        .logger(new Slf4jLogger()).requestInterceptor(new ForgerockAccessTokenInterceptor(accessToken))
                        .target(ForgerockDCRClient.class, clientRegistrationEndpoint);
        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        ClientInfo clientInfo = createClientInfoFromOauthApplicationInfo(oAuthApplicationInfo);
        ClientInfo createdApplication = forgeDCRClient.createApplication(clientInfo);
        if (createdApplication != null) {
            oAuthApplicationInfo = createOAuthAppInfoFromResponse(createdApplication);
            return oAuthApplicationInfo;
        }
        return null;
    }

    /**
     * This method will update an existing OAuth client in Forgerock Authorization Server.
     *
     * @param oAuthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        ClientInfo clientInfo = createClientInfoFromOauthApplicationInfo(oAuthApplicationInfo);
        String clientId = oAuthApplicationInfo.getClientId();
        String appInfo = apiMgtDAO.getAppInfoFromClientId(clientId, configuration.getName());
        OAuthApplicationInfo oauthRetrievedAppInfo = new Gson().fromJson(appInfo, OAuthApplicationInfo.class);
        String accessToken = (String)oauthRetrievedAppInfo.getParameter(ForgerockConstants.REGISTRATION_ACCESS_TOKEN);
        ForgerockDCRClient forgeDCRClient =
                Feign.builder().client(new OkHttpClient()).encoder(new GsonEncoder()).decoder(new GsonDecoder())
                        .logger(new Slf4jLogger()).requestInterceptor(new ForgerockAccessTokenInterceptor(
                        accessToken)).target(
                        ForgerockDCRClient.class, clientRegistrationEndpoint);
        ClientInfo clientInfoFromForgerock = forgeDCRClient.getApplication(clientId);
        if (clientInfoFromForgerock != null &&
                clientInfoFromForgerock.getApplicationType().equals(clientInfo.getApplicationType())) {
            ClientInfo updatedClientInfo = forgeDCRClient.updateApplication(clientId, clientInfo);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Updating an OAuth client in Forgerock authorization server for the" +
                        " Consumer Key %s", clientId));
            }
            return createOAuthAppInfoFromResponse(updatedClientInfo);
        } else {
            throw new APIManagementException("Error occured while updating Oauth Client in Forgerock Authorization " +
                    "server due to read-only attribute change");
        }
    }

    @Override
    public OAuthApplicationInfo updateApplicationOwner(OAuthAppRequest appInfoDTO, String owner)
            throws APIManagementException {
        return appInfoDTO.getOAuthApplicationInfo();
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param clientId consumer key of the OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public void deleteApplication(String clientId) throws APIManagementException {
        String appInfo = apiMgtDAO.getAppInfoFromClientId(clientId, configuration.getName());
        OAuthApplicationInfo oAuthApplicationInfo = new Gson().fromJson(appInfo, OAuthApplicationInfo.class);
        String accessToken = (String)oAuthApplicationInfo.getParameter(ForgerockConstants.REGISTRATION_ACCESS_TOKEN);
        ForgerockDCRClient forgeDCRClient =
                Feign.builder().client(new OkHttpClient()).encoder(new GsonEncoder()).decoder(new GsonDecoder())
                        .logger(new Slf4jLogger()).requestInterceptor(new ForgerockAccessTokenInterceptor(
                        accessToken)).target(
                        ForgerockDCRClient.class, clientRegistrationEndpoint);
        forgeDCRClient.deleteApplication(clientId);
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param clientId consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        String appInfo = apiMgtDAO.getAppInfoFromClientId(clientId, configuration.getName());
        OAuthApplicationInfo oAuthApplicationInfo = new Gson().fromJson(appInfo, OAuthApplicationInfo.class);
        String accessToken = (String)oAuthApplicationInfo.getParameter(ForgerockConstants.REGISTRATION_ACCESS_TOKEN);
        ForgerockDCRClient forgeDCRClient =
                Feign.builder().client(new OkHttpClient()).encoder(new GsonEncoder()).decoder(new GsonDecoder())
                        .logger(new Slf4jLogger()).requestInterceptor(new ForgerockAccessTokenInterceptor(
                                accessToken)).target(
                                        ForgerockDCRClient.class, clientRegistrationEndpoint);
        ClientInfo retrievedClientInfo = forgeDCRClient.getApplication(clientId);
        return createOAuthAppInfoFromResponse(retrievedClientInfo);
    }

    /**
     * Gets new access token and returns it in an AccessTokenInfo object.
     * @return AccessTokenInfo Info of the new token.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    public String getRegistrationAccessToken()
            throws APIManagementException {

        String clientId = (String) configuration.getParameter(ForgerockConstants.CLIENT_ID);
        String clientSecret = (String) configuration.getParameter(ForgerockConstants.CLIENT_SECRET);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Get new Registration access token from authorization server for the " +
                            "Consumer Key %s", clientId));
        }
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        String grantType = ForgerockConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
        parameters.add(new BasicNameValuePair(ForgerockConstants.GRANT_TYPE, grantType));
        String scopeString = "dynamic_client_registration am-introspect-all-tokens";

        parameters.add(new BasicNameValuePair(ForgerockConstants.ACCESS_TOKEN_SCOPE,
                     scopeString));

        ForgeRockAccessTokenInfo accessTokenInfo = getAccessToken(clientId, clientSecret, parameters);
        if (accessTokenInfo != null) {
            return  accessTokenInfo.getAccessToken();
        }
        return null;
    }

    /**
     * Gets new access token and returns it in an AccessTokenInfo object.
     *
     * @param accessTokenRequest Info of the token needed.
     * @return AccessTokenInfo Info of the new token.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest)
            throws APIManagementException {

        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        String clientId = accessTokenRequest.getClientId();
        String clientSecret = accessTokenRequest.getClientSecret();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Get new client access token from authorization server for the Consumer Key %s",
                    clientId));
        }
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        Object grantType = accessTokenRequest.getGrantType();
        if (grantType == null) {
            grantType = ForgerockConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
        }
        parameters.add(new BasicNameValuePair(ForgerockConstants.GRANT_TYPE, (String) grantType));
        String scopeString = convertToString(accessTokenRequest.getScope());
        if (StringUtils.isEmpty(scopeString)) {
            parameters.add(new BasicNameValuePair(ForgerockConstants.ACCESS_TOKEN_SCOPE,
                    (String) configuration.getParameter(ForgerockConstants.FORGEROCK_DEFAULT_SCOPE)));
        } else {
            parameters.add(new BasicNameValuePair(ForgerockConstants.ACCESS_TOKEN_SCOPE, scopeString));
        }

        ForgeRockAccessTokenInfo accessToken = getAccessToken(clientId, clientSecret, parameters);
        if (accessToken != null) {
            updateTokenInfo(tokenInfo, accessToken);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token has been successfully validated for the Consumer Key %s",
                        clientId));
            }
            return tokenInfo;
        } else {
            tokenInfo.setTokenValid(false);
            tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            if (log.isDebugEnabled()) {
                log.debug(String.format("OAuth token validation failed for the Consumer Key %s", clientId));
            }
        }

        return tokenInfo;
    }

    /**
     * This is used to build accesstoken request from OAuth application info.
     *
     * @param oAuthApplication OAuth application details.
     * @param tokenRequest     AccessTokenRequest that is need to be updated with addtional info.
     * @return AccessTokenRequest after adding OAuth application details.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(
            OAuthApplicationInfo oAuthApplication, AccessTokenRequest tokenRequest) throws APIManagementException {

        log.debug("Invoking buildAccessTokenRequestFromOAuthApp() method..");
        if (oAuthApplication == null) {
            return tokenRequest;
        }
        if (tokenRequest == null) {
            tokenRequest = new AccessTokenRequest();
        }
        String clientName = oAuthApplication.getClientName();
        if (oAuthApplication.getClientId() == null) {
            throw new APIManagementException(String.format("Consumer key is missing for the Application: %s",
                    clientName));
        }
        if (oAuthApplication.getClientSecret() == null) {
            log.error(String.format("Consumer Secret is missing for the Application: %s", clientName));
        }
        tokenRequest.setClientId(oAuthApplication.getClientId());
        tokenRequest.setClientSecret(oAuthApplication.getClientSecret());

        if (oAuthApplication.getParameter(ForgerockConstants.TOKEN_SCOPE) != null) {
            String[] tokenScopes = null;
            if (oAuthApplication.getParameter(ForgerockConstants.TOKEN_SCOPE) instanceof String[]) {
                tokenScopes = (String[]) oAuthApplication.getParameter(ForgerockConstants.TOKEN_SCOPE);
            }
            if (oAuthApplication.getParameter(ForgerockConstants.TOKEN_SCOPE) instanceof String) {
                tokenScopes = oAuthApplication.getParameter(ForgerockConstants.TOKEN_SCOPE).toString().split(",");
            }
            tokenRequest.setScope(tokenScopes);
            oAuthApplication.addParameter(ForgerockConstants.TOKEN_SCOPE, Arrays.toString(tokenScopes));
        }
        if (oAuthApplication.getParameter(ApplicationConstants.VALIDITY_PERIOD) != null) {
            tokenRequest.setValidityPeriod(Long.parseLong((String) oAuthApplication.getParameter(ApplicationConstants
                    .VALIDITY_PERIOD)));
        }
        Object grantType = oAuthApplication.getParameter(ForgerockConstants.TOKEN_GRANT_TYPE);
        if (grantType != null) {
            tokenRequest.setGrantType((String) grantType);
        }

        return tokenRequest;
    }


    /**
     * This is used to get the meta data of the accesstoken.
     *
     * @param accessToken AccessToken.
     * @return The meta data details of accesstoken.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Getting access token metadata from authorization server. Access token %s",
                    accessToken));
        }
        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        IntrospectInfo introspectInfo = introspectClient.introspect(accessToken);
        tokenInfo.setTokenValid(introspectInfo.isActive());

        if (tokenInfo.isTokenValid()) {

            long expiryTime = introspectInfo.getExpiry() * 1000;
            long issuedTime = introspectInfo.getIssuedAt() * 1000;
            tokenInfo.setValidityPeriod(expiryTime - issuedTime);

            if (StringUtils.isNotEmpty(introspectInfo.getScope())) {
                tokenInfo.setScope(introspectInfo.getScope().split("\\s+"));
            }

            tokenInfo.setIssuedTime(issuedTime);
            tokenInfo.setConsumerKey(introspectInfo.getClientId());
            tokenInfo.setEndUserName(introspectInfo.getSub());
            tokenInfo.addParameter(ForgerockConstants.ACCESS_TOKEN_SUBJECT, introspectInfo.getSub());
            tokenInfo.addParameter(ForgerockConstants.ACCESS_TOKEN_AUDIENCE, introspectInfo.getAudience());
            tokenInfo.addParameter(ForgerockConstants.ACCESS_TOKEN_ISSUER, introspectInfo.getAudience());
            tokenInfo.addParameter(ForgerockConstants.ACCESS_TOKEN_TYPE, introspectInfo.getTokenType());
            tokenInfo.addParameter(ForgerockConstants.ACCESS_TOKEN_USER_ID, introspectInfo.getUid());
            tokenInfo.addParameter(ForgerockConstants.ACCESS_TOKEN_IDENTIFIER, introspectInfo.getJti());
            return tokenInfo;
        }
        return null;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {

        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {

        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param oAuthAppRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        return oAuthAppRequest.getOAuthApplicationInfo();
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {

        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {

        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {

        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {
        //Not applicable
    }

    @Override
    public void deleteMappedApplication(String clientId) throws APIManagementException {
        //Not applicable
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {

        return Collections.emptySet();
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {

        return null;
    }

    /**
     * This method can be used to create a JSON Payload out of the Parameters defined in an OAuth Application
     * in order to create and update the client.
     *
     * @param oAuthApplicationInfo Object that needs to be converted.
     * @return JSON payload.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private ClientInfo createClientInfoFromOauthApplicationInfo(OAuthApplicationInfo oAuthApplicationInfo)
            throws APIManagementException {

        ClientInfo clientInfo = new ClientInfo();

        String userId = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.
                OAUTH_CLIENT_USERNAME);
        String userNameForSp = MultitenantUtils.getTenantAwareUsername(userId);
        String domain = UserCoreUtil.extractDomainFromName(userNameForSp);
        if (domain != null && !domain.isEmpty() && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(domain)) {
            userNameForSp = userNameForSp.replace(UserCoreConstants.DOMAIN_SEPARATOR, "_");
        }
        String applicationName = oAuthApplicationInfo.getClientName();
        String keyType = (String) oAuthApplicationInfo.getParameter(ApplicationConstants.APP_KEY_TYPE);
        String callBackURL = oAuthApplicationInfo.getCallBackURL();
        if (keyType != null) {
            applicationName = userNameForSp.concat(applicationName).concat("_").concat(keyType);
        }

        List<String> defaultScopes = new ArrayList<>();
        defaultScopes.add(ForgerockConstants.DEFAULT_SCOPE);
        clientInfo.setDefaultScopes(defaultScopes);
        List<String> grantTypes = new ArrayList<>();
        if (oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES) != null) {
            grantTypes =
                    Arrays.asList(
                            ((String) oAuthApplicationInfo.getParameter(APIConstants.JSON_GRANT_TYPES)).split(
                                    ","));
        }
        Object parameter = oAuthApplicationInfo.getParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES);
        Map<String, Object> additionalProperties = new HashMap<>();
        if (parameter instanceof String) {
            additionalProperties = new Gson().fromJson((String) parameter, Map.class);
        }
        clientInfo.setClientName(applicationName);
        if (grantTypes != null && !grantTypes.isEmpty()) {
            clientInfo.setGrantTypes(grantTypes);
        }
        if (StringUtils.isNotEmpty(callBackURL)) {
            String[] calBackUris = callBackURL.split(",");
            clientInfo.setRedirectUris(Arrays.asList(calBackUris));
        } else{
            // This is set as forgerock requires a redirect uri to set irrelevant of the response types.
            clientInfo.setRedirectUris(Arrays.asList(new String[]{ForgerockConstants.DEFAULT_CALLBACK}));
        }

        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_APPLICATION_TYPE)) {
            clientInfo.setApplicationType((String) additionalProperties.get(
                    ForgerockConstants.CLIENT_APPLICATION_TYPE));
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_ID)) {
            clientInfo.setClientId((String) additionalProperties.get(ForgerockConstants.CLIENT_ID));
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_SECRET)) {
            clientInfo.setClientSecret((String) additionalProperties.get(ForgerockConstants.CLIENT_SECRET));
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_URI)) {
            clientInfo.setClientUri((String) additionalProperties.get(ForgerockConstants.CLIENT_URI));
        }

        Object clientResponseTypes = additionalProperties.get(ForgerockConstants.CLIENT_RESPONSE_TYPES);
        if (clientResponseTypes != null) {
            if(clientResponseTypes instanceof List) {
                clientInfo.setResponseTypes((List) additionalProperties.get(ForgerockConstants.CLIENT_RESPONSE_TYPES));
            }
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD)) {
            clientInfo.setTokenEndpointAuthMethod(
                    (String) additionalProperties.get(ForgerockConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD));
        }
        if (additionalProperties.containsKey(ForgerockConstants.REQUEST_OBJECT_SIGNING_ALGORITHM)) {
            clientInfo.setRequestObjectSigningAlgorithm(
                    (String) additionalProperties.get(ForgerockConstants.REQUEST_OBJECT_SIGNING_ALGORITHM));
        }
        if (additionalProperties.containsKey(ForgerockConstants.JWKS)) {
            Map jwksValue = (Map) additionalProperties.get(ForgerockConstants.JWKS);
            JsonElement jsonObject = new Gson().toJsonTree(jwksValue);
            JWKS jwks = new Gson().fromJson(jsonObject, JWKS.class);
            clientInfo.setJwks(jwks);
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_ACCESS_TOKEN_LIFETIME)) {
            Object accessTokenLifeTime = additionalProperties.get(ForgerockConstants.CLIENT_ACCESS_TOKEN_LIFETIME);
            // This is to handle a ui issue where the type of the object returned is different
            // compared to creating and updating
            if(accessTokenLifeTime instanceof Double) {
                double accessTokenLT = (double) additionalProperties.get(ForgerockConstants.CLIENT_ACCESS_TOKEN_LIFETIME);
                clientInfo.setAccessTokenLifeTime((long) accessTokenLT);
            } else {
                clientInfo.setAccessTokenLifeTime(Long.parseLong((String)
                        additionalProperties.get(ForgerockConstants.CLIENT_ACCESS_TOKEN_LIFETIME)));
            }
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_REFRESH_TOKEN_LIFETIME)) {
            Object refreshTokenLifeTime = additionalProperties.get(ForgerockConstants.CLIENT_REFRESH_TOKEN_LIFETIME);
            // This is to handle a ui issue where the type of the object returned is different
            // compared to creating and updating
            if(refreshTokenLifeTime instanceof Double) {
                double refreshTokenLT = (double) additionalProperties.get(ForgerockConstants.CLIENT_REFRESH_TOKEN_LIFETIME);
                clientInfo.setRefreshTokenLifeTime((long) refreshTokenLT);
            } else {
                clientInfo.setRefreshTokenLifeTime(Long.parseLong((String)
                        additionalProperties.get(ForgerockConstants.CLIENT_REFRESH_TOKEN_LIFETIME)));
            }
        }
        if (additionalProperties.containsKey(ForgerockConstants.CLIENT_AUTH_CODE_LIFETIME)) {
            // This is to handle a ui issue where the type of the object returned is different
            // compared to creating and updating
            Object authCodeLifeTime = additionalProperties.get(ForgerockConstants.CLIENT_AUTH_CODE_LIFETIME);
            if(authCodeLifeTime instanceof Double) {
                double authCodeLT = (double) additionalProperties.get(ForgerockConstants.CLIENT_AUTH_CODE_LIFETIME);
                clientInfo.setAuthCodeLifeTime((long) authCodeLT);
            } else {
                clientInfo.setAuthCodeLifeTime(Long.parseLong((String)
                        additionalProperties.get(ForgerockConstants.CLIENT_AUTH_CODE_LIFETIME)));
            }
        }
        return clientInfo;
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param clientInfo Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppInfoFromResponse(ClientInfo clientInfo) {

        OAuthApplicationInfo appInfo = new OAuthApplicationInfo();
        appInfo.setClientName(clientInfo.getClientName());
        appInfo.setClientId(clientInfo.getClientId());
        appInfo.setClientSecret(clientInfo.getClientSecret());
        appInfo.addParameter(ForgerockConstants.REGISTRATION_ACCESS_TOKEN, clientInfo.getRegistrationAccessToken());
        if (clientInfo.getRedirectUris() != null) {
            appInfo.setCallBackURL(String.join(",", clientInfo.getRedirectUris()));
        }

        if (clientInfo.getGrantTypes() != null) {
            appInfo.addParameter(ForgerockConstants.CLIENT_GRANT_TYPES,
                    String.join(" ", clientInfo.getGrantTypes()));
        }
        if (StringUtils.isNotEmpty(clientInfo.getClientName())) {
            appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_NAME, clientInfo.getClientName());
        }
        if (StringUtils.isNotEmpty(clientInfo.getClientId())) {
            appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_ID, clientInfo.getClientId());
        }
        if (StringUtils.isNotEmpty(clientInfo.getClientSecret())) {
            appInfo.addParameter(ApplicationConstants.OAUTH_CLIENT_SECRET, clientInfo.getClientSecret());
        }
        String additionalProperties = new Gson().toJson(clientInfo);
        appInfo.addParameter(APIConstants.JSON_ADDITIONAL_PROPERTIES, new Gson().fromJson(
                additionalProperties, Map.class));
        return appInfo;
    }

    /**
     * Gets an access token.
     *
     * @param clientId     clientId of the oauth client.
     * @param clientSecret clientSecret of the oauth client.
     * @param parameters   list of request parameters.
     * @return an {@code JSONObject}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private ForgeRockAccessTokenInfo getAccessToken(String clientId, String clientSecret,
                                                    List<NameValuePair> parameters) throws
            APIManagementException {

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            String tokenEndpoint = (String) configuration.getParameter(APIConstants.KeyManager.TOKEN_ENDPOINT);
            HttpPost httpPost = new HttpPost(tokenEndpoint);
            httpPost.setEntity(new UrlEncodedFormEntity(parameters));
            String encodedCredentials = getEncodedCredentials(clientId, clientSecret);

            httpPost.setHeader(ForgerockConstants.AUTHORIZATION,
                    ForgerockConstants.AUTHENTICATION_BASIC + encodedCredentials);
            if (log.isDebugEnabled()) {
                log.debug("Invoking HTTP request to get the accesstoken.");
            }
            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            if (entity == null) {
                handleException(String.format(ForgerockConstants.STRING_FORMAT,
                        ForgerockConstants.ERROR_COULD_NOT_READ_HTTP_ENTITY, response));
            }
            String content = "";
            try (InputStream inputStream = entity.getContent()) {
                content = IOUtils.toString(inputStream);

            }
            if (HttpStatus.SC_OK == statusCode) {

                return new Gson().fromJson(content, ForgeRockAccessTokenInfo.class);
            } else {
                ForgerockError error = new Gson().fromJson(content, ForgerockError.class);
                handleError(response.getStatusLine(), error.toString());
            }
        } catch (UnsupportedEncodingException e) {
            handleException(ForgerockConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        } catch (IOException e) {
            handleException(ForgerockConstants.ERROR_OCCURRED_WHILE_READ_OR_CLOSE_BUFFER_READER, e);
        }
        return null;
    }

    /**
     * Update the access token info after getting new access token.
     *
     * @param tokenInfo Token info need to be updated.
     * @return AccessTokenInfo
     */
    private AccessTokenInfo updateTokenInfo(AccessTokenInfo tokenInfo,
                                            ForgeRockAccessTokenInfo accessToken) {

        tokenInfo.setAccessToken(accessToken.getAccessToken());

        tokenInfo.setValidityPeriod(accessToken.getExpiry() * 1000);

        tokenInfo.setScope(accessToken.getScope().split("\\s+"));

        return tokenInfo;
    }

    /**
     * Returns a space separate string from list of the contents in the string array.
     *
     * @param stringArray an array of strings.
     * @return space separated string.
     */
    private static String convertToString(String[] stringArray) {

        if (stringArray != null) {
            StringBuilder sb = new StringBuilder();
            List<String> strList = Arrays.asList(stringArray);
            for (String s : strList) {
                sb.append(s);
                sb.append(" ");
            }
            return sb.toString().trim();
        }

        return null;
    }

    /**
     * Returns base64 encoded credentaials.
     *
     * @param clientId     clientId of the oauth client.
     * @param clientSecret clientSecret of the oauth clients.
     * @return String base64 encode string.
     */
    private static String getEncodedCredentials(String clientId, String clientSecret) throws APIManagementException {

        String encodedCredentials;
        try {
            encodedCredentials = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret)
                    .getBytes(ForgerockConstants.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new APIManagementException(ForgerockConstants.ERROR_ENCODING_METHOD_NOT_SUPPORTED, e);
        }

        return encodedCredentials;
    }

    /**
     * Common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private static void handleException(String msg) throws APIManagementException {

        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * Common method to throw exceptions. This will only expect one parameter.
     *
     * @param statusLine error status coming from Forgerock as a StatusLine.
     * @param msg        error message as a String.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private static void handleError(StatusLine statusLine, String msg) throws APIManagementException {
        log.error(msg);
        ErrorItem errorItem = new ErrorItem();
        errorItem.setStatusCode(statusLine.getStatusCode());
        errorItem.setDescription(statusLine.getReasonPhrase());
        errorItem.setMessage(msg);
        throw new APIManagementException(msg, errorItem);
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {

        ClientInfo updateInfo = new ClientInfo();
        updateInfo.setClientId(accessTokenRequest.getClientId());
        updateInfo.setClientSecret(accessTokenRequest.getClientSecret());
        ClientInfo clientInfo = forgeDCRClient.updateApplication(accessTokenRequest.getClientId(), updateInfo);
        return clientInfo.getClientSecret();

    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String apiIdsString) throws APIManagementException {


        Map<String, Set<Scope>> apiToScopeMapping = new HashMap<>();
        ApiMgtDAO apiMgtDAO = ApiMgtDAO.getInstance();
        Map<String, Set<String>> apiToScopeKeyMapping = apiMgtDAO.getScopesForAPIS(apiIdsString);
        for (String apiId : apiToScopeKeyMapping.keySet()) {
            Set<Scope> apiScopes = new LinkedHashSet<>();
            Set<String> scopeKeys = apiToScopeKeyMapping.get(apiId);
            for (String scopeKey : scopeKeys) {
                Scope scope = getScopeByName(scopeKey);
                apiScopes.add(scope);
            }
            apiToScopeMapping.put(apiId, apiScopes);
        }
        return apiToScopeMapping;
    }

    @Override
    public void registerScope(Scope scope) throws APIManagementException {

    }

    @Override
    public Scope getScopeByName(String name) throws APIManagementException {

        return null;
    }

    @Override
    public Map<String, Scope> getAllScopes() throws APIManagementException {

        return null;
    }

    @Override
    public void attachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

    }

    @Override
    public void updateResourceScopes(API api, Set<String> oldLocalScopeKeys, Set<Scope> newLocalScopes,
                                     Set<URITemplate> oldURITemplates, Set<URITemplate> newURITemplates)
            throws APIManagementException {

    }

    @Override
    public void detachResourceScopes(API api, Set<URITemplate> uriTemplates) throws APIManagementException {

    }

    @Override
    public void deleteScope(String scopeName) throws APIManagementException {

    }

    @Override
    public void updateScope(Scope scope) throws APIManagementException {

    }

    @Override
    public boolean isScopeExists(String scopeName) throws APIManagementException {

        return false;
    }

    @Override
    public void validateScopes(Set<Scope> scopes) throws APIManagementException {

    }

    @Override
    public String getType() {

        return ForgerockConstants.KM_TYPE;
    }
}
