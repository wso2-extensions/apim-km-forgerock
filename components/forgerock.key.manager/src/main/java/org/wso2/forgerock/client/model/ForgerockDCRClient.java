package org.wso2.forgerock.client.model;

import feign.Headers;
import feign.Param;
import feign.RequestLine;

public interface ForgerockDCRClient {

    @RequestLine("POST")
    @Headers("Content-Type: application/json")
    public ClientInfo createApplication(ClientInfo clientInfo);

    @RequestLine("GET ?client_id={client_id}")
    @Headers("Content-Type: application/json")
    public ClientInfo getApplication(@Param("client_id") String clientId);

    @RequestLine("PUT ?client_id={client_id}")
    @Headers("Content-Type: application/json")
    public ClientInfo updateApplication(@Param("client_id") String clientId, ClientInfo clientInfo);

    @RequestLine("DELETE ?client_id={client_id}")
    @Headers("Content-Type: application/json")
    public void deleteApplication(@Param("client_id") String clientId);

}
