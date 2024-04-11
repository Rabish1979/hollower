#pragma once
#include "restclient-cpp/connection.h"
#include "restclient-cpp/restclient.h"
#include "json/json.h"

const string API_KEY = "^%&%*&*&^BDBKBDDJVJHDVJHDVDV"; 

class RestWrapper
{
public:
    void static SendInfo(string &host, string &body)
    {
        // initialize RestClient
        RestClient::init();

        // get a connection object
        RestClient::Connection* conn = new RestClient::Connection(host);

        // configure basic auth
        conn->SetBasicAuth("WarMachine68", "WARMACHINEROX");

        conn->SetTimeout(15);
        conn->SetUserAgent("helloclient/2.0");

        // enable following of redirects (default is off)
        conn->FollowRedirects(true);
        conn->FollowRedirects(true, 3);

        // set headers
        RestClient::HeaderFields headers;
        headers["Accept"] = "application/json";
        conn->SetHeaders(headers);

        // append additional headers
        conn->AppendHeader("Authorization", API_KEY);

        // RestClient::Response r = conn->get("/processes");
        RestClient::Response response = conn->post("/processes", body);
        RestClient::disable();
    }
};

