package com.test.api.Response;

public class LogoutResponse
{
    private String token;
    private String type = "Bearer";

    public LogoutResponse(String accessToken)
    {
        this.token = accessToken;
    }

    public String getAccessToken()
    {
        return token;
    }

    public void setAccessToken(String accessToken)
    {
        this.token = accessToken;
    }
}
