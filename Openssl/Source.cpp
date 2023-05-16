#include <iostream>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <string>
#include <fstream>
#include <vector>
#include <assert.h>
#include <sqlite3.h>




double get_file(std::vector<std::string>& vec,std::ifstream &file,std::string& source)
{

    std::string address;
    wchar_t symbol;
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

        }
    
    return count;
}


void check_address(std::string &str)
{
    size_t size=0;
    size = str.find("://");
    if  (size!=std::string::npos)
    {
        str.erase(0, size + 3);
    }         

    size = str.find('/');
    if (size != std::string::npos)
    {
        str.erase(size, str.length() - size);
    }
  
}

class Certification
{
private:

    int errSock=0;
    int errSSL=0;
    char buf[1024];
    char buf_Ip[256];
    std::string address;
    std::string port;
    std::string destin;

    WSADATA wsa;
    WORD version = MAKEWORD(2, 2); 

    SOCKET Sock;
    addrinfo hints;
    addrinfo* res;

    SSL* ssl;
    X509* certif;
    SSL_CTX* ctx;
    BIO* bio_out;
    EVP_PKEY* pub_key;
    SSL_CIPHER const* cipher;
    SSL_SESSION* session;
  

    void check_Sock_error(int err);

    void check_SSL_error(int err);


    void SocketCreate();
 
    void SocketConnection();

    void getMethod();

    void getSSL();

    void bind_sock_ssl();

    void SSLConnect();

    void getCert();

    void getBiofile();

    void getKey();

    void getCipher();

public:
    Certification(std::string &address,std::string &port,std::string destination) : address(address),port(port),destin(destination)   {   }


    void fillAddr();

    void print();

    int get_errors();

    void ip_to_ad();
 

    ~Certification()
    {
        closesocket(Sock);
        WSACleanup();
        BIO_free(bio_out);
        X509_free(certif);
        SSL_CTX_free(ctx);
        SSL_free(ssl);
        
    }
};


void Certification::check_Sock_error(int err)
{
    if (err !=0)
    {
        std::cerr << "Socket error\n" << std::endl;
        return;
    }
}


void Certification::check_SSL_error(int err)
{
    if (err == 0 || err < 0)
    {
        return;
    }
}


int Certification::get_errors()
{
    if (errSock == 0 && errSSL == 1)
    {
        return 0;
    }
    else {
        return 1;
    }
}


void Certification::fillAddr()
{

    errSock = WSAStartup(version, &wsa);
    check_Sock_error(errSock);
    check_address(address);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    errSock =getaddrinfo(address.c_str(), port.c_str(), &hints, &res);
    if (errSock != 0)
    {
        return;
    }

    ip_to_ad();
    SocketCreate();
}


void Certification::ip_to_ad()
{
    addrinfo *ptr;
    void* add; 
    ptr = res;

        if (ptr->ai_family == AF_INET)
        {
            sockaddr_in* ipv4 = (sockaddr_in*)ptr->ai_addr;
            add = &(ipv4->sin_addr);
        }
        else {
            sockaddr_in6* ipv6 = (sockaddr_in6*)ptr->ai_addr;
            add = &(ipv6->sin6_addr);
        }
      
        inet_ntop(ptr->ai_family, add, buf_Ip, sizeof(buf_Ip));
}


void Certification::SocketCreate()
{
    Sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (Sock == INVALID_SOCKET)
    {
        return;
    }
    else {
        SocketConnection();
    }
}


void Certification::SocketConnection()
{
    errSock = connect(Sock, res->ai_addr, res->ai_addrlen);
    check_Sock_error(errSock);

    getMethod();
}


void Certification::getMethod()
{
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_method());
    if (!ctx)
    {
        std::cerr << "SSL Error" << std::endl;
        return;
    }
    else {
        getSSL();
    }
}


void Certification::getSSL()
{
  
    ssl=SSL_new(ctx);
    if (!ctx)
    {
        std::cerr << "SSL Error" << std::endl;
        return;
    }
    else {
        bind_sock_ssl();
    }

}


void Certification::bind_sock_ssl()
{

    errSSL = SSL_set_fd(ssl, Sock);
    check_SSL_error(errSSL);
    SSLConnect();

}


void Certification::SSLConnect()
{
    errSSL = SSL_connect(ssl);
    session = SSL_get0_session(ssl);
    check_SSL_error(errSSL);
    getCert();
}


void Certification::getCert()
{
    certif = SSL_get1_peer_certificate(ssl);
    if (!certif)
    {
        return;
    }
    else {
        getBiofile();
    }
}


void Certification::getBiofile()
{

    std::string str = destin + address + ".pem";

    bio_out = BIO_new_file(str.c_str(), "a");
    if (bio_out == 0)
    {
        std::cout<<address << ":  Error creating file" << std::endl;
    }
    else {
        getKey();
        getCipher();
    }

   
    //X509_print(bio_out, certif);
    //PEM_write_bio_X509(bio_out, certif);

}


void Certification::getKey()
{
    pub_key = X509_get0_pubkey(certif);
    EVP_PKEY_print_public(bio_out, pub_key, 2, 0);

}


void Certification::getCipher()
{
    cipher = SSL_get_current_cipher(ssl);
    SSL_CIPHER_description(cipher, buf, sizeof(buf));

    BIO_printf(bio_out, "===============================================Cipher===============================================\n");
    BIO_printf(bio_out, buf, sizeof(buf));
}


void Certification::print()
{
    std::cout<<buf_Ip<<"\t"<< address << ":\tKEY\t" << pub_key << std::endl;
    std::cout << address <<":\tCIPHER\t"<< buf;
    std::cout <<address<<": connection currently in use\t"<< SSL_get_version(ssl) << std::endl<<std::endl;
 
}


//#define DEBUG

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
        bool flag = true;
        char symbol='0';
        std::string address="google.com";
        std::string port = "443";
        std::string source="sor.txt";
        std::string destination="D:\dz\praktika\Tests\Openssl\Openssl";
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

        do
        {
            if (flag == false)
            {
                count = 1;
                std::cout << i / count * 100 << "%" << " - " << vec[i] << std::endl;
            }
            else {
                std::cout << i / count * 100 << "%" << " - " << vec[i] << std::endl;
              }

             Certification C(vec[i], port, destination);
             C.fillAddr();
             err = C.get_errors();
             if (err == 0)
             {
                 C.print();
             }   
             else {
                 std::cerr<<vec[i] << ":\tAddress getting error\n" << std::endl;
             }
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

    system("pause");
    return 0;
}