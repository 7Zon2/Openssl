#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string>
#include <fstream>
#include <vector>


//#define DEBUG




double get_file(std::vector<std::string>& vec,std::ifstream &file,std::string& source)
{

    std::string address;
    char symbol;
    double count=0;

        file.open(source, std::fstream::in);
        if (!file.is_open())
        {
            std::cerr << "File open error" << std::endl;
            exit(1);
        }
        else {
            while (!file.eof())
            {
                file >> address;
                symbol = file.get();
                if ((symbol == ' ') || (symbol == '\n'))
                {
                    vec.push_back(address);
                    ++count;
                }

            }
            file.close();
            vec.push_back(address);

        }
    
    return count;
}


//class Certification
//{
//private:
//
//    int errSock;
//    int errSSL;
//    std::wstring address;
//    std::wstring port;
//
//    WSADATA wsa;
//    WORD version = MAKEWORD(2, 2); 
//
//    SOCKET Sock;
//    addrinfoW hints;
//    addrinfoW* res;
//
//    SSL* ssl;
//    X509* certif;
//    SSL_CTX* ctx;
//
//    void check_Sock_error(int err);
//
//    void check_SSL_error(int err);
//
//    void fillAddr();
//
//    void SocketCreate();
// 
//    void SocketConnection();
//
//    void getMethod();
//
//    void getSSL();
//
//    void bind_sock_ssl();
//
//    void SSLConnect();
//
//    void getCert();
//
//public:
//    Certification(std::wstring &address,std::wstring &port) : address(address),port(port)
//    {
//        errSock = WSAStartup(version, &wsa);
//        check_Sock_error(errSock);
//        SSLeay_add_ssl_algorithms();
//        SSL_load_error_strings();
//        fillAddr();
//    }
//
//
//    ~Certification()
//    {
//        closesocket(Sock);
//        WSACleanup();
//    }
//};
//
//
//void Certification::check_Sock_error(int err)
//{
//    if (err == SOCKET_ERROR)
//    {
//        std::cerr << "Socket error" << std::endl;
//        exit(1);
//    }
//}
//
//
//void Certification::check_SSL_error(int err)
//{
//    if (err == 0 || err < 0)
//    {
//        std::cerr << "SSl Error" << SSL_get_error(ssl, err);
//    }
//}
//
//
//void Certification::fillAddr()
//{
//    memset(&hints, 0, sizeof(hints));
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_TCP;
//
//    errSock = GetAddrInfoW(address.c_str(), port.c_str(), &hints, &res);
//    check_Sock_error(errSock);
//
//    SocketCreate();
//}
//
//
//void Certification::SocketCreate()
//{
//    Sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
//    if (Sock == INVALID_SOCKET)
//    {
//        exit(1);
//    }
//    else {
//        SocketConnection();
//    }
//}
//
//
//void Certification::SocketConnection()
//{
//    errSock = connect(Sock, res->ai_addr, res->ai_addrlen);
//    check_Sock_error(errSock);
//
//    getMethod();
//}
//
//
//void Certification::getMethod()
//{
//    ctx = SSL_CTX_new(TLS_method());
//    if (ctx == 0 || ctx < 0)
//    {
//        std::cerr << "SSL Error" << std::endl;
//        exit(1);
//    }
//    else {
//        getSSL();
//    }
//}
//
//
//void Certification::getSSL()
//{
//    ssl=SSL_new(ctx);
//    if (ctx == 0 || ctx < 0)
//    {
//        std::cerr << "SSL Error" << std::endl;
//        exit(1);
//    }
//    else {
//        bind_sock_ssl();
//    }
//
//}
//
//void Certification::bind_sock_ssl()
//{
//    errSSL = SSL_set_fd(ssl, Sock);
//    check_SSL_error(errSSL);
//    SSLConnect();
//
//}
//
//
//void Certification::SSLConnect()
//{
//    errSSL = SSL_connect(ssl);
//    check_SSL_error(errSSL);
//    getCert();
//}
//
//
//void Certification::getCert()
//{
//    
//}

/*=================================================================================================================================================*/



int main(int argc,char* argv[])
{
#ifdef DEBUG

    for (int i = 0; i < argc; i++)
    {
        std::cout << i << "  " << argv[i] << std::endl;
    }

    if (argc > 1) {


        if (argv[1][0] != '-')
        {
            std::cout << "Command error" << std::endl;
            return 1;
        }

#endif // DEBUG
        int32_t err = 0;
        double count = 0;
        double i = 0;
        bool flag = 1;
        char symbol='0';
        std::string address="vk.com";
        std::string port = "443";
        std::string source="D:\\dz\\praktika\\Tests\\Openssl\\x64\\Release\\sor.txt";
        std::string destination="D:\\dz\\praktika\\Tests\\Openssl\\Openssl";
        std::ifstream file;
        std::vector<std::string> vec;
#ifdef DEBUG

        switch (tolower(argv[1][1]))
        {
            case 's':   address = argv[2]; destination = argv[3]; flag = false; break;

            case 'f':   source = argv[2];  destination = argv[3]; flag = true; break;

            default: std::cout << "Command error" << std::endl;   return 1;
        }
#endif // DEBUG

        if (flag == true)
        {            
            count=get_file(vec, file, source);
        }
        else {
            vec.push_back(address);
        }

        do {

            if (flag == false)
            {
                i = 1;
                count = 1;
                std::cout << i / count * 100 << "%" << " - " << vec[i] << std::endl;
            }
            else {
                std::cout << i / count * 100 << "%" << " - " << vec[i] << std::endl;
            }
          

            WSADATA wsa;
            WORD version = MAKEWORD(2, 2);
            err = WSAStartup(version, &wsa);
            if (err == SOCKET_ERROR)
            {
                std::cerr << "WSASrartup Error  " << WSAGetLastError() << std::endl;
                exit(1);
            }


            addrinfo hints;
            addrinfo* res;

            memset(&hints, 0, sizeof(addrinfo));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            err = getaddrinfo(address.c_str(), port.c_str(), &hints, &res);
            if (err == SOCKET_ERROR)
            {
                std::cerr << "geraddrinfo Error" << WSAGetLastError() << std::endl;
                exit(1);
            }

            SOCKET Sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (Sock == INVALID_SOCKET)
            {
                std::cerr << "Socket Error" << GetLastError() << std::endl;
                closesocket(Sock);
                exit(1);
            }

            err = connect(Sock, res->ai_addr, res->ai_addrlen);
            if (err != 0)
            {
                std::cerr << "Eror connected" << GetLastError() << std::endl;
                closesocket(Sock);
                exit(1);
            }

            SSLeay_add_ssl_algorithms();
            SSL_load_error_strings();

            SSL* ssl;
            X509* certif;
            SSL_CTX* ctx;

            ctx = SSL_CTX_new(TLS_method());
            if (ctx != 0)
            {
                ssl = SSL_new(ctx);
                if (ssl != 0)
                {
                    err = SSL_set_fd(ssl, Sock);
                    if (err != -1)
                    {
                        err = SSL_connect(ssl);
                        if (err != 0)
                        {
                            certif = SSL_get1_peer_certificate(ssl);
                            if (certif != 0)
                            {
                                vec[i] = destination+vec[i] + ".pem";
                                 BIO* bio_out;
                                 bio_out = BIO_new_file(vec[i].c_str(), "w");
                                 X509_print(bio_out, certif);
                                 PEM_write_bio_X509(bio_out, certif);
                                 BIO_free(bio_out);
                                 std::ifstream F_source;

                            }
                            else {
                                std::cerr << "Error certificate" << std::endl;
                            }
                            X509_free(certif);
                        }
                        else
                        {
                            std::cerr << "Error SSL_connect" << std::endl;
                        }
                    }
                    else
                    {
                        std::cerr << "SSL_set_fd Error" << std::endl;
                    }
                }
                else
                {
                    std::cerr << "SSL Error" << std::endl;
                }
                SSL_free(ssl);
            }
            else
            {
                std::cerr << "SSL_CTX_new Error" << std::endl;
            }

            SSL_CTX_free(ctx);
            closesocket(Sock);
            WSACleanup();

            ++i;

        } while (i < count);
#ifdef DEBUG

    }
    else 
    {
        std::cout << "Too few arguments. If you want to input the one address use this command: -s google.com D:\\... " << std::endl<<
                     "if you want to enter adrresses from a file use another command: -f D:\\sourse.txt D:\\destination"<<std::endl;
    }
#endif // DEBUG

    return 0;
}