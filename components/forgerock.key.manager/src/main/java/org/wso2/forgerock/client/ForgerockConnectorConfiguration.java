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

package org.wso2.forgerock.client;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.KeyManagerConnectorConfiguration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component(
        name = "forgerock.configuration.component",
        immediate = true,
        service = KeyManagerConnectorConfiguration.class
)
public class ForgerockConnectorConfiguration implements KeyManagerConnectorConfiguration {

    @Override
    public String getImplementation() {

        return ForgerockOAuthClient.class.getName();
    }

    @Override
    public String getJWTValidator() {

        return ForgerockJWTValidatoImpl.class.getName();
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_ID, "Client ID", "input", "Client ID of service Application", "",
                        true,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_SECRET, "Client Secret", "input",
                        "Client Secret of service Application", "", true,
                        true, Collections.emptyList(), false));
        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_APPLICATION_TYPE, "Application Type", "select", "Type Of Application to " +
                        "create", "web", false,
                        false, Arrays.asList("web", "native", "service", "browser"), false));
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_RESPONSE_TYPES, "Response Type", "select", "Type Of Token response", "",
                        false,
                        false, Arrays.asList("code", "token", "id_token"), true));
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_ACCESS_TOKEN_LIFETIME, "Access Token Lifetime",
                        "input", "Life Time of the Access Token", "0", false,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_REFRESH_TOKEN_LIFETIME, "Refresh Token Lifetime",
                        "input", "Life Time of the Refresh Token", "0", false,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_AUTH_CODE_LIFETIME, "Authorization code Lifetime",
                        "input", "Life Time of the Authorization code", "0", false,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto(ForgerockConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD,
                        "Token endpoint Authentication Method", "select", "How to Authenticate Token Endpoint",
                        "client_secret_basic", false, true, Arrays.asList("client_secret_basic", "client_secret_post",
                        "client_secret_jwt"), false));
        configurationDtoList.add(
                new ConfigurationDto(ForgerockConstants.CLIENT_TYPE, ForgerockConstants.CLIENT_TYPE_LABEL,
                        ForgerockConstants.INPUT_TYPE_SELECT, ForgerockConstants.CLIENT_TYPE_TOOLTIP,
                        ForgerockConstants.CLIENT_TYPE_DEFAULT_VALUE, false, false,
                        Arrays.asList("Confidential", "Public"), false));
        configurationDtoList.add(
                new ConfigurationDto(ForgerockConstants.CLIENT_DEFAULT_SCOPE, ForgerockConstants.DEFAULT_SCOPE_LABEL,
                        ForgerockConstants.INPUT_TYPE_INPUT, ForgerockConstants.DEFAULT_SCOPE_TOOLTIP,
                        ForgerockConstants.DEFAULT_VAlUE_EMPTY, false, false, Arrays.asList("default"), true));
        return configurationDtoList;     
    }

    @Override
    public String getType() {

        return ForgerockConstants.KM_TYPE;
    }

    @Override
    public String getDefaultScopesClaim() {

        return ForgerockConstants.SCOPE;
    }

    @Override
    public String getDefaultConsumerKeyClaim() {

        return ForgerockConstants.AUD;
    }
}
