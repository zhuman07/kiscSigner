#include <memory>
#include <cstdlib>
#include <iostream>
#include <restbed>
#include "json.hpp"
#include "signData.h"

using namespace std;
using namespace restbed;

void method_handler(const shared_ptr<Session> session)
{
    const auto request = session->get_request();
    
    int content_length;
    request->get_header(string("Content-Length"), content_length, 0);
    session->fetch(content_length, [](const shared_ptr<restbed::Session> session, const Bytes &body)
    {
        nlohmann::json data = nlohmann::json::parse(restbed::String::to_string(body));
        cout << "post: " << data["data"] << endl;

        string profile("profile://MyProfile");
        string dataToSign(data["data"]);
        unsigned char signedData[8192];
        nlohmann::json response = {
            {"success", false},
            {"message", ""},
            {"data", ""}
        };

        if (kiscSigner::signData(&profile, &dataToSign, signedData)) {
            response["data"] = reinterpret_cast<char*>(signedData);
            if (kiscSigner::verify(&profile, &dataToSign, signedData)) {
                response["success"] = true;
            } else {
                response["message"] = "failed to verify signature";
            }
        } else {
            response["message"] = "failed to sign data";
        }

        cout << "data: " << dataToSign << endl;
        cout << "signed data: " << signedData << endl;

        session->close(OK, response.dump(), {{"Content-Type", "application/json"}});
    });
}

int main( const int, const char** )
{
    cout << "Service start" << endl;
    auto resource = make_shared< Resource >( );
    resource->set_path( "/sign" );
    resource->set_method_handler( "POST", method_handler );

    auto settings = make_shared< Settings >( );
    settings->set_port( 3851 );
    settings->set_default_header( "Connection", "close" );

    Service service;
    service.publish( resource );
    service.start( settings );

    cout << "Service end" << endl;
    return EXIT_SUCCESS;
}