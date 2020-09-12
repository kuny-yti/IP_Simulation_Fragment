#include "ip_common.h"


#if defined( __WIN32__ ) || defined( _WIN32 )

static const struct ap_init
{
    bool is_init;
    ap_init()
    {
        is_init = true;
        static WSAData wsadata;
        if (::WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
        {
            if (::WSAStartup(MAKEWORD(2,0), &wsadata) != 0)
                is_init = false;
        }
    }
    ~ap_init()
    {
        ::WSACleanup();
    }
}os_ap;

#endif

quint16 IP::CheckSum(quint16* buffer, int size)
{
    quint32 cksum = 0;
    while(size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(quint16);
    }
    if(size)
        cksum += *(quint8*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (quint16)(~cksum);
}

IP::Header IP::MakeHeaderIP()
{
    Header head;
    head.version = DefaultVersion;
    head.headlen = DefaultIHL;
    head.tos = 0;
    head.length = 0;
    head.id = 0;
    head.foff = 0;
    head.ttl = DefaultTTL;
    head.protocol = DefaultProtocol;
    head.checksum = 0;
    head.addrs = 0;
    head.addrd = 0;
    return head;
}
quint16 IP::HashID (char* v, int len)
{
    quint32 hash = 5381;
    for (int i = 0; i < len; ++i)
        hash = (hash + (hash << 5)) + v[i];
    return quint16((hash >>16) | ((hash << 16) >> 16));
}
