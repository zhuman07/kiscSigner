#include <memory>
#include <cstdlib>
#include <restbed>
#include "json.hpp"
#include "signData.h"

using json = nlohmann::json;
using namespace std;
using namespace restbed;

void method_handler(const shared_ptr<Session> session)
{
    const auto request = session->get_request();

    char *profile = "PCIDTEST.P0201020";
    string data = string{"hello world!"};
    unsigned char *dataToSign = reinterpret_cast<unsigned char*>(const_cast<char*>(data.c_str()));
    unsigned char *signedData;
    int result = kiscSigner::signData(profile, dataToSign, signedData);

    fprintf(stdout, "data: %s\nsigned data: %s\n", dataToSign, signedData);

    int content_length = request->get_header( "Content-Length", 0 );
    session->fetch( content_length, [ ]( const shared_ptr< restbed::Session > session, const Bytes & body )
    {
        //json body = json::parse(body.data());
        
        fprintf( stdout, "%.*s\n", ( int ) body.size( ), body.data( ) );
        session->close( OK, "Hello, World!", { { "Content-Length", "13" } } );
    } );
}

int main( const int, const char** )
{
    auto resource = make_shared< Resource >( );
    resource->set_path( "/sign" );
    resource->set_method_handler( "POST", method_handler );

    auto settings = make_shared< Settings >( );
    settings->set_port( 3851 );
    settings->set_default_header( "Connection", "close" );

    Service service;
    service.publish( resource );
    service.start( settings );

    return EXIT_SUCCESS;
}