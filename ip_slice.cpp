#include "ip_slice.h"
#include <QTime>
#include <QDataStream>


ip_slice::ip_slice(const qint16 mtu):
    MTU(mtu)
{
    frame = 0;
    head = IP::MakeHeaderIP();
}
ip_slice::~ip_slice()
{

}

void ip_slice::set_tos(IP::ToSPriority prio, IP::ToSSubfield subf)
{
    head.priority = prio;
    head.subfield = subf;
}
void ip_slice::set_mtu(const int value)
{
    MTU = value;
}
void ip_slice::set_protocol(IP::Protocol p)
{
    head.protocol = p;
}
void ip_slice::set_addr_src(const QString &ip)
{
    head.addrs = ::inet_addr(ip.toLatin1().data());
}
void ip_slice::set_addr_dst(const QString &ip)
{
    head.addrd = ::inet_addr(ip.toLatin1().data());
}
/*
static quint32 current_ts()
{
    QTime tm = QTime::currentTime();
    return (tm.hour() << 22) | (tm.minute() << 16) | (tm.second() << 10) | tm.msec();
};*/
IP::DataPackList ip_slice::fragment (const QByteArray &data)
{
    IP::DataPackList out;

    IP::DataPack ipdp(MTU);
    char        *ptr   = (char*)data.data();
    ::memcpy(ipdp.head(), &head, sizeof(head));

    const quint16 hlen = (ipdp.head()->headlen <<2);
    const quint32 dlen = data.size()+ hlen;

    const quint32 buf[] = {ipdp.head()->addrs, ipdp.head()->addrd, dlen, frame++};
    ipdp.head()->id = IP::HashID((char*)buf, sizeof(buf));
    ipdp.head()->flag = IP::IP_Congestion;
    ipdp.head()->length = dlen;
    ipdp.head()->checksum = IP::CheckSum((quint16*)ipdp.head(), sizeof(IP::Header));

    // 小于MTU大小不分片
    if (dlen <= MTU)
    {
        ::memcpy(ipdp.data(), ptr, dlen - hlen);
        out.append(ipdp);
        return out;
    }

    // 超出MTU大小，进行分片
    for (int total = dlen -hlen, offset = 0, num = (MTU - hlen);
         total > 0;
         total -= num, offset += num, num = (total < num) ? total : num)
    {
        ::memcpy(ipdp.data(), ptr + offset, num);

        ipdp.head()->flag = IP::IP_MoreFragment;

        ipdp.head()->offset = (offset >>3);
        ipdp.head()->length = num + (ipdp.head()->headlen <<2);
        ipdp.head()->checksum = IP::CheckSum((quint16*)ipdp.head(), sizeof(IP::Header));

        out.append(ipdp);
    }

    return out;
}

IP::DataPackList ip_slice::direct(const QByteArray &data)
{
    IP::DataPackList out;

    IP::DataPack ipdp(MTU);
    char        *ptr   = (char*)data.data();
    ::memcpy(ipdp.head(), &head, sizeof(head));

    const quint16 hlen = (ipdp.head()->headlen <<2);
    const quint32 dlen = data.size()+ hlen;

    if (dlen <= MTU)
    {
        const quint32 buf[] = {ipdp.head()->addrs, ipdp.head()->addrd, dlen, frame++};
        ipdp.head()->flag = IP::IP_Congestion;
        ipdp.head()->id = IP::HashID((char*)buf, sizeof(buf));
        ipdp.head()->length = dlen;
        ipdp.head()->checksum = IP::CheckSum((quint16*)ipdp.head(), sizeof(IP::Header));

        ::memcpy(ipdp.data(), ptr, dlen - hlen);
        out.append(ipdp);
        return out;
    }

    // 超出MTU大小，进行多次分发
    for (int total = dlen -hlen, offset = 0, num = (MTU - hlen);
         total > 0;
         total -= num, offset += num, num = (total < num) ? total : num)
    {
        ::memcpy(ipdp.data(), ptr + offset, num);

        ipdp.head()->flag = IP::IP_DontFragment;
        ipdp.head()->length = num + (ipdp.head()->headlen <<2);
        const quint32 rebuf[] = {ipdp.head()->addrs, ipdp.head()->addrd, dlen, frame++};
        ipdp.head()->id = IP::HashID((char*)rebuf, sizeof(rebuf));
        ipdp.head()->checksum = IP::CheckSum((quint16*)ipdp.head(), sizeof(IP::Header));

        out.append(ipdp);
    }

    return out;
}


//!
//! \brief pack 封装
//! \param list
//! \return
//!
QByteArray ip_slice::pack(const IP::DataPackList &list)
{
    QByteArray out;
    foreach (const IP::DataPack &var, list)
        out.append((char*)var.pack(), var.head()->length);
    return out;
}
