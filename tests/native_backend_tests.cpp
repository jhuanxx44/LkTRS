#include "lktrs/protocol/native_process.hpp"
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using lktrs::protocol::NativeProcess;
namespace {
void require(bool value,const std::string& message){if(!value)throw std::runtime_error(message);}
// This parser is restricted to base64 strings returned by the owned test
// backend. Product callers should use a JSON parser for the general protocol.
std::string signature(const std::string& response){
    const std::string name="\"signature_b64\":\"";const auto start=response.find(name);
    require(start!=std::string::npos,"missing signature");const auto pos=start+name.size();const auto end=response.find('"',pos);
    require(end!=std::string::npos,"unterminated signature");return response.substr(pos,end-pos);
}
std::string call(NativeProcess& process,const std::string& request,bool success=true){
    const std::vector<std::uint8_t> payload(request.begin(),request.end());
    const auto bytes=process.request(payload,std::chrono::minutes(10));const std::string response(bytes.begin(),bytes.end());
    require(response.find(success?"\"ok\":true":"\"ok\":false")!=std::string::npos,"unexpected native response: "+response);
    return response;
}
}
int main(int argc,char**argv){
    if(argc!=2)return 2;
    try{
        NativeProcess process(argv[1],{"--stdio"});
        call(process,R"({"op":"info"})");
        call(process,R"({"op":"setup","capacity":4})");
        for(const auto* q:{R"({"op":"keygen","user":"alice","account":"a"})",R"({"op":"keygen","user":"alice","account":"b"})",R"({"op":"keygen","user":"bob","account":"c"})",R"({"op":"join","account":"a"})",R"({"op":"join","account":"b"})",R"({"op":"join","account":"c"})"})call(process,q);
        const std::string issue(64,'1');const std::string common="\"issue\":\""+issue+"\",\"k\":3,";
        // A failed first signing request must not pin a different quota.
        call(process,"{\"op\":\"sign\",\"account\":\"unknown\",\"issue\":\""+issue+"\",\"k\":9,\"message_b64\":\"bTE=\",\"timestamp\":99}",false);
        auto a=signature(call(process,"{\"op\":\"sign\",\"account\":\"a\","+common+"\"message_b64\":\"bTE=\",\"timestamp\":100}"));
        auto b=signature(call(process,"{\"op\":\"sign\",\"account\":\"b\","+common+"\"message_b64\":\"bTI=\",\"timestamp\":101}"));
        auto verify=[&](const std::string&sig,const std::string&msg,bool ok){return call(process,"{\"op\":\"verify\","+common+"\"message_b64\":\""+msg+"\",\"signature_b64\":\""+sig+"\"}",ok);};
        require(verify(a,"bTE=",true).find("\"verified\":true")!=std::string::npos,"verification flag missing");
        verify(a,"bTI=",false);
        const std::string pair=common+"\"message_b64\":\"bTE=\",\"signature_b64\":\""+a+"\",\"second_message_b64\":\"bTI=\",\"second_signature_b64\":\""+b+"\"";
        require(call(process,"{\"op\":\"link\","+pair+"}").find("\"linked\":true")!=std::string::npos,"link failed");
        require(call(process,"{\"op\":\"trace\","+pair+"}").find("\"trace\":\"legal\"")!=std::string::npos,"legal trace failed");
        call(process,R"({"op":"exit","account":"a"})");verify(a,"bTE=",false);
        auto after=signature(call(process,"{\"op\":\"sign\",\"account\":\"b\","+common+"\"message_b64\":\"bTM=\",\"timestamp\":102}"));verify(after,"bTM=",true);
        call(process,"{\"op\":\"sign\",\"account\":\"b\","+common+"\"message_b64\":\"bTM=\",\"timestamp\":103}",false);
        // A consumed issue cannot be reopened by changing the quota.
        call(process,"{\"op\":\"sign\",\"account\":\"b\",\"issue\":\""+issue+"\",\"k\":4,\"message_b64\":\"bTM=\",\"timestamp\":104}",false);
        call(process,R"({"op":"revoke_user","user":"alice"})");verify(after,"bTM=",false);
        call(process,R"({"op":"join","account":"b"})",false);
        std::cout<<"PASS: C++ -> native Groth16 setup/keygen/join/sign/verify/link/trace/exit/quota/revocation\n";
        return 0;
    }catch(const std::exception&e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
