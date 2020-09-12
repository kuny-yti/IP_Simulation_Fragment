#ifndef IP_INTERFACE_H
#define IP_INTERFACE_H

#include <QByteArray>
#include <QString>
#include <QObject>
#include <QQueue>
#include "ip_common.h"
#include "ip_slice.h"
#include "ip_frag.h"

class ip_interface : public QObject
{
    Q_OBJECT
public:
    //!
    //! \brief ip_interface 用文件作为管道构建接口(默认用内存作为管道构建接口)
    //! \param frag_file
    //!
    explicit ip_interface(const QString &frag_file = QString());

    ~ip_interface();

    //!
    //! \brief create 创建创建模拟器
    //! \param addr
    //! \param protl
    //! \param prio
    //! \param subf
    //! \return
    //!
    bool create(const QString &addr, IP::Protocol protl,
                IP::ToSPriority prio = IP::ToS_Routine,
                IP::ToSSubfield subf = IP::ToS_Normal);

    //!
    //! \brief cancel 取消模拟器
    //! \return
    //!
    void cancel();

    //!
    //! \brief send 提供给传输层进行数据发送
    //! \param addr 目的地址
    //! \param data 发送的数据(TCP、UDP、ICMP等协议已经封装在内)
    //! \return
    //!
    bool send(const QByteArray &data);

signals :
    //!
    //! \brief recv 当发送后经内部线程分片/重组后将重组的数据通过此信号发送出来
    //! \param data 重组的数据
    //!
    void recv(const QByteArray &data);

private:
    struct thread_sync *sync;
    struct send_thread *sthrd;
    struct recv_thread *rthrd;
    friend struct send_thread;
    friend struct recv_thread;
    friend struct thread_sync;
};

#endif // IP_INTERFACE_H
