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
    private static String GET_KEY_MAPPING_INFO_FROM_CLIENT_ID = "SELECT APP_INFO FROM AM_APPLICATION_KEY_MAPPING " +
            "WHERE CONSUMER_KEY = ? and KEY_MANAGER = ?";
    private static String GET_APPINFO_FROM_UUID_OF_KEY_MANAGER = "SELECT APP_INFO FROM AM_APPLICATION_KEY_MAPPING " +
            "WHERE CONSUMER_KEY = ? and KEY_MANAGER = (SELECT UUID FROM AM_KEY_MANAGER WHERE NAME = ? AND " +
            "TENANT_DOMAIN = ?)";

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

        try (Connection connection = APIMgtDBUtil.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(GET_KEY_MAPPING_INFO_FROM_CLIENT_ID)) {
            preparedStatement.setString(1, clientId);
            preparedStatement.setString(2, configuration.getName());
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    try (InputStream appInfo = resultSet.getBinaryStream(ForgerockConstants.APP_UNFO)) {
                        if (appInfo != null) {
                            return (IOUtils.toString(appInfo));
                        }
                    } catch (IOException e) {
                        throw new APIManagementException("Error while retrieving metadata", e);
                    }
                }
                return getAppInfoFromKeyanerUUID(connection, configuration, clientId);
            }
        } catch (SQLException e) {
            throw new APIManagementException("Error while Retrieving Key Mappings ", e);
        }
    }

    private String getAppInfoFromKeyanerUUID(Connection connection, KeyManagerConfiguration configuration,
                                             String clientId) throws SQLException, APIManagementException {

        try (PreparedStatement getAppInfoFromUUIDPreparedStatement = connection.prepareStatement(
                GET_APPINFO_FROM_UUID_OF_KEY_MANAGER)) {
            getAppInfoFromUUIDPreparedStatement.setString(1, clientId);
            getAppInfoFromUUIDPreparedStatement.setString(2, configuration.getName());
            getAppInfoFromUUIDPreparedStatement.setString(3, configuration.getTenantDomain());
            try (ResultSet resultSet = getAppInfoFromUUIDPreparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    try (InputStream appInfo = resultSet.getBinaryStream(ForgerockConstants.APP_UNFO)) {
                        if (appInfo != null) {
                            return (IOUtils.toString(appInfo));
                        }
                    } catch (IOException e) {
                        throw new APIManagementException("Error while retrieving metadata", e);
                    }
                }
            }
        }
        return null;
    }
}
