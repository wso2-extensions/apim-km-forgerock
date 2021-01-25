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

import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.jwt.JWTValidatorImpl;

import java.util.List;

/**
 * This class provides the extended implementation for "Forgerock" for JWT Validation
 */
public class ForgerockJWTValidatoImpl  extends JWTValidatorImpl {

    @Override
    protected String getConsumerKey(JWTClaimsSet jwtClaimsSet) throws APIManagementException {
        if (jwtClaimsSet != null) {
            if (jwtClaimsSet.getAudience() != null) {
                List<String> audience = jwtClaimsSet.getAudience();
                return audience.get(0).toString();
            }
        }
        return null;
    }
}
