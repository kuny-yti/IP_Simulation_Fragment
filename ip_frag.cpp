#include "ip_frag.h"

ip_frag::ip_frag()
{

}
ip_frag::~ip_frag()
{

}

//!
//! \brief unpack 解封
//! \param bin
//! \return
//!
IP::DataPackList ip_frag::unpack(const QByteArray &in)
{
    IP::DataPackList out;
    const char *ptr = in.data();
    const int len = in.size();
    for (int offset = 0; offset < len; )
    {
        IP::Header *hdr = (IP::Header *)(ptr + offset);
        offset += hdr->length;
        out.append(IP::DataPack(hdr));
    }
    return out;
}

bool ip_frag::check(IP::Header *rhs)const
{
    IP::Header tmhdr = *rhs;
    tmhdr.checksum = 0;
    const quint16 csum = IP::CheckSum((quint16*)&tmhdr, sizeof(IP::Header));
    return csum == rhs->checksum;
}
//!
//! \brief ip_frag::is_match 匹配id，源地址，目的地址，和协议。是否相同
//! \param first
//! \param rhs
//! \return
//!
bool ip_frag::is_match(IP::Header *first, IP::Header *rhs)const
{
    return (first->id == rhs->id) &&
            (first->addrs == rhs->addrs) &&
            (first->addrd == rhs->addrd) &&
            (first->protocol == rhs->protocol);
}

QByteArray ip_frag::reassemble(const IP::DataPackList &dpl)
{
    QByteArray out;
    IP::Header *first_hdr = 0;
    foreach (const IP::DataPack &var, dpl)
    {
        // 校验和是否合法
        if (check(var.head()))
            continue;

        // 匹配多个分片
        if (!first_hdr)
            first_hdr = var.head();
        else if (!is_match(first_hdr, var.head()))
            continue;

        const quint16 length = var.head()->length - (var.head()->headlen <<2);

        // 有多个分片，取出分片内的数据
        if (var.head()->flag & IP::IP_MoreFragment)
        {
            const quint16 offset = var.head()->offset <<3;
            out.insert(offset, var.data(), length);
        }
        // 非分片，则不考虑数据的偏移
        else if (var.head()->flag & IP::IP_DontFragment)
        {
            out.append(var.data(), length);
        }
        // 单帧数据取出后返回
        else
        {
            out = QByteArray(var.data(), length);
            break;
        }
    }

    return out;
}
