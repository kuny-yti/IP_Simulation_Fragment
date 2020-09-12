#ifndef IP_SLICE_H
#define IP_SLICE_H

#include "ip_common.h"
#include <QList>

// TCP/IP模拟分片
class ip_slice
{
public:
    explicit ip_slice(const qint16 mtu = IP::DefaultMTU);
    ~ip_slice();

    void set_addr_src(const QString &ip);
    void set_addr_dst(const QString &ip);
    void set_protocol(IP::Protocol p);
    void set_mtu(const int value);
    void set_tos(IP::ToSPriority prio, IP::ToSSubfield subf);

    //!
    //! \brief fragment 分片处理
    //! \param data
    //! \return
    //!
    IP::DataPackList fragment(const QByteArray &data);

    //!
    //! \brief direct 直接处理
    //! \param data
    //! \return
    //!
    IP::DataPackList direct(const QByteArray &data);


public:
    //!
    //! \brief pack 封装
    //! \param list
    //! \return
    //!
    static QByteArray pack(const IP::DataPackList &list);

private:
    quint16    MTU;
    quint32    frame;
    IP::Header head;
};

#endif // IP_SLICE_H
