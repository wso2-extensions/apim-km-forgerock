package org.wso2.forgerock.client;

import com.github.jknack.handlebars.internal.lang3.StringUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.dto.JWTValidationInfo;
import org.wso2.carbon.apimgt.impl.jwt.JWTValidatorImpl;
import org.wso2.carbon.apimgt.impl.jwt.SignedJWTInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
