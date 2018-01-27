#pragma once

#include <string>
#include <vector>
#include <cstring>

#ifdef NO_SFML
#include <SFML/System.hpp>
#endif

#ifdef _WIN32
#define _WIN32_WINNT 0x601
#include <ws2tcpip.h>
#define CLOSE(x) closesocket(x)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#define CLOSE(x) close(x)
#endif

#include <assert.h>

#define SERVERPORT "6950"

static int32_t canary_start = 0xdeadbeef;
static int32_t canary_end = 0xafaefead;

// get sockaddr, IPv4 or IPv6:
inline
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

struct udp_sock
{
    int sock;
    bool good;
    bool udp_connected = false;

    udp_sock(int _sock)
    {
        sock = _sock;

        good = sock >= 0;
    }

    udp_sock()
    {
        sock = -1;

        good = false;
    }

    void make_invalid()
    {
        good = false;
    }

    bool valid()
    {
        return good;
    }

    bool invalid()
    {
        return !valid();
    }

    int& get()
    {
        return sock;
    }

    void close()
    {
        CLOSE(sock);

        make_invalid();
    }

    std::string get_peer_ip()
    {
        if(!valid())
            return "127.0.0.1";

        sockaddr_storage addr;

        socklen_t found_size = sizeof(addr);

        int ret = getpeername(sock, (sockaddr*)&addr, &found_size);

        in_addr inaddr = ((sockaddr_in*)&addr)->sin_addr;

        ///https://msdn.microsoft.com/en-us/library/windows/desktop/ms740496(v=vs.85).aspx
        char* localIP = inet_ntoa(inaddr);

        return std::string(localIP);
    }

    std::string get_peer_port()
    {
        if(!valid())
            return SERVERPORT;

        sockaddr_storage addr;

        socklen_t found_size = sizeof(addr);

        int ret = getpeername(sock, (sockaddr*)&addr, &found_size);

        int theirport = ntohs(((sockaddr_in*)&addr)->sin_port);

        return std::string(std::to_string(theirport));
    }

    std::string get_host_ip()
    {
        if(!valid())
            return "127.0.0.1";

        sockaddr_storage addr;

        socklen_t found_size = sizeof(addr);

        int ret = getsockname(sock, (sockaddr*)&addr, &found_size);

        in_addr inaddr = ((sockaddr_in*)&addr)->sin_addr;

        char* localIP = inet_ntoa(inaddr);

        return std::string(localIP);
    }

    std::string get_host_port()
    {
        if(!valid())
            return SERVERPORT;

        sockaddr_storage addr;

        socklen_t found_size = sizeof(addr);

        int ret = getsockname(sock, (sockaddr*)&addr, &found_size);

        int theirport = ntohs(((sockaddr_in*)&addr)->sin_port);

        return std::string(std::to_string(theirport));
    }

    sockaddr_storage get_peer_sockaddr()
    {
        sockaddr_storage addr;

        socklen_t found_size = sizeof(addr);

        getpeername(sock, (sockaddr*)&addr, &found_size);

        return addr;
    }

    bool operator==(const udp_sock& o)
    {
        return sock == o.sock;
    }
};

inline
bool operator==(sockaddr_storage& s1, sockaddr_storage& s2)
{
    sockaddr_in* si1 = (sockaddr_in*)&s1;
    sockaddr_in* si2 = (sockaddr_in*)&s2;

    if(si1->sin_port == si2->sin_port &&
       si1->sin_addr.s_addr == si2->sin_addr.s_addr)
        return true;

    return false;
}

inline
std::string get_addr_ip(sockaddr_storage& addr)
{
    in_addr inaddr = ((sockaddr_in*)&addr)->sin_addr;

    ///https://msdn.microsoft.com/en-us/library/windows/desktop/ms740496(v=vs.85).aspx
    char* localIP = inet_ntoa(inaddr);

    return std::string(localIP);
}

inline
std::string get_addr_port(sockaddr_storage& addr)
{
    int theirport = ntohs(((sockaddr_in*)&addr)->sin_port);

    return std::string(std::to_string(theirport));
}

inline
sockaddr_storage get_sockaddr_from(const std::string& ip, const std::string& port)
{
    int portid = atoi(port.c_str());
    unsigned long addr = inet_addr(ip.c_str());

    struct addrinfo hints, *servinfo;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    sockaddr_storage ret;
    memset(&ret, 0, sizeof(sockaddr_storage));

    if ((rv = getaddrinfo(ip.c_str(), port.c_str(), &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return sockaddr_storage();
    }

    /*for(addrinfo* p = servinfo; p != nullptr; p = p->ai_next) {
        sockaddr_in* ipv4 = (sockaddr_in*)p->ai_addr;

        memcpy(&ret, ipv4, sizeof(sockaddr_in));
    }*/

    memcpy(&ret, servinfo->ai_addr, servinfo->ai_addrlen);

    freeaddrinfo(servinfo);

    return ret;
}

inline
bool sock_set_non_blocking(udp_sock& sock, int is_non_blocking)
{
    if(sock.invalid())
        return true;

    unsigned long val = is_non_blocking > 0;

    int res = ioctlsocket(sock.get(), FIONBIO, &val);

    if(res != 0)
    {
        printf("Error %i making socket non blocking\n", res);
    }

    return res == 0;
}

inline
bool sock_set_non_blocking(int sock, int is_non_blocking)
{
    udp_sock s(sock);

    return sock_set_non_blocking(s, is_non_blocking);
}

inline
bool sock_readable(udp_sock& sock)
{
    //if(!sock.valid())
    //    return false;

    fd_set fds;
    struct timeval tmo;

    int sval = sock.get();

    tmo.tv_sec=0;
    tmo.tv_usec=0;

    FD_ZERO(&fds);
    FD_SET((UINT32)sval, &fds);

    select(sval+1, &fds, NULL, NULL, &tmo);

    return FD_ISSET((uint32_t)sval, &fds);
}

inline
bool sock_writable(udp_sock& sock, long seconds = 0, long milliseconds = 0)
{
    //if(!sock.valid())
    //    return false;

    fd_set fds;
    struct timeval tmo;

    int sval = sock.get();

    tmo.tv_sec=seconds;
    tmo.tv_usec=milliseconds;

    FD_ZERO(&fds);
    FD_SET((UINT32)sval, &fds);

    select(sval+1, NULL, &fds, NULL, &tmo);

    return FD_ISSET((uint32_t)sval, &fds);
}

inline
bool sock_readable(int sock)
{
    udp_sock s(sock);

    return sock_readable(s);
}

inline
bool sock_writable(int sock, long seconds = 0, long milliseconds = 0)
{
    udp_sock s(sock);

    return sock_writable(s, seconds, milliseconds);
}

inline
udp_sock conditional_accept(udp_sock& sock)
{
    if(!sock_readable(sock))
        return udp_sock(-1);

    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof their_addr;

    int new_fd = accept(sock.get(), (struct sockaddr *)&their_addr, &addr_len);

    udp_sock new_sock(new_fd);

    return new_sock;
}

inline
int udp_send(udp_sock& sock, const char* data, int len)
{
    if(len == 0)
        return 0;

    if(data == nullptr)
        return 0;

    if(sock.invalid())
        return -1;

    int num = -1;

    if((num = send(sock.get(), data, len, 0)) == -1)
    {
        sock.make_invalid();

        return -1;
    }

    return num;
}

inline
int udp_send(udp_sock& sock, const std::vector<char>& msg)
{
    if(msg.size() == 0)
        return 0;

    return udp_send(sock, &msg[0], msg.size());
}

inline
int udp_send(udp_sock& sock, const std::string& data)
{
    return udp_send(sock, data.c_str(), data.length());
}

///dont use, internal
inline
bool udp_pipe_connect(udp_sock& sock, const std::string& address, const std::string& port)
{
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(address.c_str(), port.c_str(), &hints, &servinfo)) != 0) {
        printf("getaddrinfo: %s\n", gai_strerror(rv));
        return false;
    }

    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if(connect(sock.sock, p->ai_addr, p->ai_addrlen) == -1) {

        }

        break;
    }

    sock.udp_connected = true;

    return true;
}

inline bool udp_pipe_connect(udp_sock& sock, const struct sockaddr *addr)
{
    int addrlen = sizeof(sockaddr_storage);

    int err = connect(sock.sock, addr, addrlen);

    if(err == -1)
    {
        printf("pipe err\n");
        return false;
    }

    sock.udp_connected = true;

    return true;
}

inline std::vector<char> udp_recv(udp_sock& sock)
{
    if(sock.invalid())
        return std::vector<char>();

    constexpr int MAXDATASIZE = 100000;
    static char buf[MAXDATASIZE];

    int num = -1;

    if ((num = recv(sock.get(), buf, MAXDATASIZE-1, 0)) == -1)
    {
        return std::vector<char>();
    }

    buf[num] = '\0';

    std::vector<char> ret(buf, buf + num);

    return ret;
}

inline
std::vector<char> udp_receive_from(udp_sock& sock, sockaddr_storage* store, int* len = nullptr)
{
    if(sock.invalid())
        return std::vector<char>();

    constexpr int MAXDATASIZE = 100000;
    static char buf[MAXDATASIZE];

    //*len = sizeof(sockaddr_storage);

    int llen = sizeof(sockaddr_storage);

    int num = -1;

    if ((num = recvfrom(sock.get(), buf, MAXDATASIZE-2, 0, (sockaddr*)store, &llen)) == -1) {

        //if(errno != EAGAIN && errno != EWOULDBLOCK)
        //    sock.make_invalid();

        return std::vector<char>();
    }

    if(len)
        *len = llen;

    buf[num] = '\0';

    std::vector<char> ret(buf, buf + num);

    return ret;
}

inline
int udp_send_to(udp_sock& sock, const std::vector<char>& data, const sockaddr* to_addr)
{
    int llen = sizeof(sockaddr_storage);

    int ret = sendto(sock.sock, data.data(), data.size(), 0, to_addr, llen);

    //if(ret == SOCKET_ERROR)
    //    sock.make_invalid();

    return ret;
}

inline
bool networking_init()
{
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);
    #endif // _WIN32
}

inline
udp_sock udp_host(const std::string& serverport = SERVERPORT)
{
    networking_init();

    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, serverport.c_str(), &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            CLOSE(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        udp_sock bad;
        bad.make_invalid();
        return bad;
    }

    freeaddrinfo(servinfo);

    return udp_sock(sockfd);
}

inline
udp_sock udp_connect(const std::string& address, const std::string& serverport)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(address.c_str(), serverport.c_str(), &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(1);
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        exit(2);
    }

    udp_sock sock(sockfd);

    udp_pipe_connect(sock, address, serverport);

    return sock;
}


inline
udp_sock udp_getsocket()
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(sock == INVALID_SOCKET)
        printf("error");

    return udp_sock(sock);
}

#ifdef NO_SFML
struct sock_info
{
    int sock;
    sf::Clock clk;
    float timeout_delay; ///in ms
    bool finished; ///now invalid

    sock_info(int _sock, float _timeout_delay = 0) : sock_info()
    {
        sock = _sock;
        timeout_delay = _timeout_delay;
    }

    sock_info(int _sock, unsigned long seconds, unsigned long microseconds) : sock_info()
    {
        float ms1 = (float)microseconds / 1000.f;
        float ms2 = (float)seconds * 1000.f;

        sock = _sock;
        timeout_delay = ms1 + ms2;
    }

    sock_info()
    {
        sock = -1;
        timeout_delay = 0;
        finished = false;
    }

    void retry()
    {
        sock = -1;
        finished = false;
        clk.restart();
    }

    bool within_timeout()
    {
        float t = clk.getElapsedTime().asMicroseconds() / 1000.f;

        if(t < timeout_delay || timeout_delay == 0)
            return true;

        return false;
    }

    bool connected()
    {
        return sock_writable(sock);
    }

    bool valid()
    {
        return within_timeout() && connected() && !finished && sock != -1;
    }

    bool owns_socket()
    {
        return !finished;
    }

    void close()
    {
        if(sock != -1)
            CLOSE(sock);
    }

    int get()
    {
        //sock_disable_nagle(sock);

        finished = true;

        return sock;
    }
};
#endif

struct byte_vector
{
    std::vector<char> ptr;

    template<typename T>
    void push_back(T v)
    {
        char* pv = (char*)&v;

        for(uint32_t i=0; i<sizeof(T); i++)
        {
            ptr.push_back(pv[i]);
        }
    }

    template<typename T>
    void push_back(T* v, int n)
    {
        for(int i=0; i<n; i++)
        {
            ptr.push_back(((uint8_t*)v)[i]);
        }
    }

    template<typename T>
    void push_string(T v, int n)
    {
        for(int i=0; i<n; i++)
        {
            ptr.push_back(v[i]);
        }
    }

    void push_vector(const byte_vector& vec)
    {
        for(int i=0; i<vec.ptr.size(); i++)
        {
            ptr.push_back(vec.ptr[i]);
        }
    }

    std::vector<char> data()
    {
        return ptr;
    }
};

#include <iostream>

struct byte_fetch
{
    std::vector<char> ptr;

    int internal_counter;

    byte_fetch()
    {
        internal_counter = 0;
    }

    template<typename T>
    void push_back(T v)
    {
        char* pv = (char*)&v;

        for(int i=0; i<sizeof(T); i++)
        {
            ptr.push_back(pv[i]);
        }
    }

    void push_back(const std::vector<char>& v)
    {
        ptr.insert(ptr.end(), v.begin(), v.end());
    }

    template<typename T>
    T get()
    {
        int prev = internal_counter;

        internal_counter += sizeof(T);

        if(internal_counter > (int)ptr.size())
        {
            std::cout << "Error, invalid bytefetch" << std::endl;

            return T();
        }

        return *(T*)&ptr[prev];
    }

    void* get(int size)
    {
        int prev = internal_counter;

        internal_counter += size;

        return (void*)&ptr[prev];
    }

    std::vector<char> get_buf(int size)
    {
        int prev = internal_counter;

        internal_counter += size;

        std::vector<char> dat;

        /*if(internal_counter > (int)ptr.size())
        {
            printf("Error in get_buf\n");
        }*/

        if(internal_counter > ptr.size())
        {
            std::cout << "Error invalid getbuf" << std::endl;
            return std::vector<char>();
        }

        for(int i=prev; i<internal_counter; i++)
        {
            dat.push_back(ptr[i]);
        }



        return dat;
    }

    bool finished()
    {
        return internal_counter >= (int)ptr.size();
    }
};



