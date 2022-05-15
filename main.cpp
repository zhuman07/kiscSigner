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
        DWORD signLength;
        
        nlohmann::json response = {
            {"success", false},
            {"message", ""},
            {"data", ""}
        };
        string signatureData;

        if (kiscSigner::signData(&profile, &dataToSign, signedData, &signLength)) {
            
            /*for (int i = 0; i < sizeof(signedData)/sizeof(signedData[0]); i++)
            {
                char buff[4];
                sprintf(buff, "%02x", (unsigned char)signedData[i]);
                signatureData = signatureData + buff;
            }*/
            //*signedData = {};
            if (kiscSigner::verify(&profile, &dataToSign, signedData, &signLength)) {

                std::stringstream ss;
                for (DWORD i = 0; i < 8192; i++) {
                    ss << std::hex << std::setfill('0') << std::setw(2) << (short)signedData[8192 - i - 1];
                }
                signatureData = ss.str();

                response["success"] = true;
                response["data"] = signatureData;//reinterpret_cast<char*>(signedData);
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