/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
                .add(new ConfigurationDto("accessToken", "Registration AccessToken", "input",
                        "Access Token Generated From Forgerock UI", "", true, true, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("client_id", "Client ID", "input", "Client ID of service Application", "",
                        true,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("client_secret", "Client Secret", "input",
                        "Client Secret of service Application", "", true,
                        true, Collections.emptyList(), false));
        return configurationDtoList;
    }

    @Override
    public List<ConfigurationDto> getApplicationConfigurations() {

        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto("application_type", "Application Type", "select", "Type Of Application to " +
                        "create", "web", false,
                        false, Arrays.asList("web", "native", "service", "browser"), false));
        configurationDtoList
                .add(new ConfigurationDto("response_types", "Response Type", "select", "Type Of Token response", "",
                        false,
                        false, Arrays.asList("code", "token", "id_token"), true));
        configurationDtoList
                .add(new ConfigurationDto("access_token_lifetime", "Access Token Lifetime",
                        "input", "Life Time of the Access Token", "3600", false,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("refresh_token_lifetime", "Refresh Token Lifetime",
                        "input", "Life Time of the Refresh Token", "60", false,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("auth_code_lifetime", "Authorization code Lifetime",
                        "input", "Life Time of the Authorization code", "60", false,
                        false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("token_endpoint_auth_method", "Token endpoint Authentication Method",
                        "select", "How to Authenticate Token Endpoint", "client_secret_basic", false,
                        true, Arrays.asList("client_secret_basic", "client_secret_post", "client_secret_jwt"), false));
        return configurationDtoList;
    }

    @Override
    public String getType() {

        return "ForgeRock";
    }

    @Override
    public String getDefaultScopesClaim() {

        return ForgerockConstants.SCOPE;
    }

    @Override
    public String getDefaultConsumerKeyClaim() {

        return ForgerockConstants.CID;
    }
}
