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

    //char *profile = reinterpret_cast<char*>(const_cast<char*>(string("FSystem").c_str())); //PCIDTEST.P0201020
    char *profile = "profile://MyProfile";
    string data = string{"hello world!"};
    unsigned char *dataToSign = reinterpret_cast<unsigned char*>(const_cast<char*>(data.c_str()));
    unsigned char *signedData;
    int result = kiscSigner::signData(profile, dataToSign, signedData);

    fprintf(stdout, "data: %s\n signed data: %s\n", dataToSign, signedData);
    int content_length;
    request->get_header(string("Content-Length"), content_length, 0);
    session->fetch(content_length, [signedData, content_length](const shared_ptr<restbed::Session> session, const Bytes &body)
    {
        nlohmann::json json_body = {
            {"result", "hello world"}
        };
        //fprintf(stdout, "%.*s\n", (int)body.size(), body.data());
        session->close(OK, json_body.dump(), {{"Content-Type", "application/json"}});
    });
    //delete[] profile;
    //delete[] dataToSign;
    //delete[] signedData;
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