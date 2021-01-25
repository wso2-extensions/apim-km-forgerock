package org.wso2.forgerock.client.dao;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.utils.APIMgtDBUtil;
import org.wso2.forgerock.client.ForgerockConstants;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * This class provides the DAO implementation for "Forgerock" connector
 */
public class ForgerockApiMgtDAO {

    private static ForgerockApiMgtDAO INSTANCE = new ForgerockApiMgtDAO();
    private static final Log log = LogFactory.getLog(ForgerockApiMgtDAO.class);

    /**
     * Method to get the instance of the ApiMgtDAO.
     *
     * @return {@link ForgerockApiMgtDAO} instance
     */
    public static ForgerockApiMgtDAO getInstance() {
        return INSTANCE;
    }

    private ForgerockApiMgtDAO() {
    }

    /**
     * Method returns the appInfo relevant to a consumer key and key manager type.
     *
     * @param clientId      consumer key of the app
     * @param configuration Key manager configuration
     * @return String app info as a string
     * @throws APIManagementException This is the custom exception class for API management
     */
    public String getAppInfoFromClientId(String clientId, KeyManagerConfiguration configuration)
            throws APIManagementException {
        String GET_KEY_MAPPING_INFO_FROM_CLIENT_ID = "SELECT APP_INFO FROM AM_APPLICATION_KEY_MAPPING WHERE " +
                "CONSUMER_KEY = ? and KEY_MANAGER = ?";
        String GET_UUID_OF_KEY_MANAGER = "SELECT UUID FROM AM_KEY_MANAGER WHERE NAME = ?";
        try (Connection connection = APIMgtDBUtil.getConnection();
             PreparedStatement preparedStatement = connection
                     .prepareStatement(GET_KEY_MAPPING_INFO_FROM_CLIENT_ID)) {
            preparedStatement.setString(1, clientId);
            preparedStatement.setString(2, configuration.getName());
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    try (InputStream appInfo = resultSet.getBinaryStream(ForgerockConstants.APP_UNFO)) {
                        if (appInfo != null) {
                            return (IOUtils.toString(appInfo));
                        }
                    } catch (IOException e) {
                        log.error("Error while retrieving metadata", e);
                    }
                }
                PreparedStatement getUUIDPreparedStatement = connection.prepareStatement(GET_UUID_OF_KEY_MANAGER);
                getUUIDPreparedStatement.setString(1, configuration.getName());
                try (ResultSet uuidSet = getUUIDPreparedStatement.executeQuery()) {
                    while (uuidSet.next()) {
                        String uuid = uuidSet.getString(ForgerockConstants.UUID);
                        if (uuid != null) {
                            preparedStatement.setString(2, uuid);
                            ResultSet resultSetByUUID = preparedStatement.executeQuery();
                            if (resultSetByUUID != null) {
                                while (resultSetByUUID.next()) {
                                    try (InputStream appInfo = resultSetByUUID.getBinaryStream(
                                            ForgerockConstants.APP_UNFO)) {
                                        if (appInfo != null) {
                                            return (IOUtils.toString(appInfo));
                                        }
                                    } catch (IOException e) {
                                        log.error("Error while retrieving metadata", e);
                                    }
                                }
                            }
                        } else {
                            log.error("Error while retrieving UUID of Key Manager");
                        }
                    }
                }
            }
        } catch (SQLException e) {
            throw new APIManagementException("Error while Retrieving Key Mappings ", e);
        }
        return null;
    }
}
