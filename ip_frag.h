#ifndef IP_FRAG_H
#define IP_FRAG_H

#include "ip_common.h"

// TCP/IP模拟分片重组
class ip_frag
{
public:
    ip_frag();
    ~ip_frag();

    QByteArray reassemble(const IP::DataPackList &dpl);

public:
    //!
    //! \brief unpack 解封
    //! \param bin
    //! \return
    //!
    static IP::DataPackList unpack(const QByteArray &bin);

protected:
    bool check(IP::Header *rhs)const;
    bool is_match(IP::Header *first, IP::Header *rhs)const;
};

#endif // IP_FRAG_H
