#include "ip_interface.h"
#include <QFile>
#include <QWaitCondition>
#include <QMutex>
#include <QThread>

struct thread_sync
{
    QString        file;
    QByteArray     mem;
    QMutex         mutex;
    QWaitCondition cond;
};

struct send_thread : public QThread
{
    volatile bool      flag;
    QQueue<QByteArray> queue;
    ip_slice           slice;
    thread_sync       *sync;

    send_thread(const QString &addr, IP::Protocol protl,
                IP::ToSPriority prio, IP::ToSSubfield subf)
    {
        slice.set_mtu(IP::DefaultMTU);
        slice.set_addr_src(IP::DefaultSourceAddr);
        slice.set_addr_dst(addr);
        slice.set_protocol(protl);
        slice.set_tos(prio, subf);

        flag = true;
        this->start();
    }
    ~send_thread()
    {
        flag = false;
        this->wait(300);
        this->terminate();
    }

    //!
    //! \brief write 向底层写入数据
    //! \param data
    //!
    void write (const QByteArray &data)
    {
        queue.enqueue(data);
    }

    void run() override
    {
        while (flag)
        {
            // 队列内有数据则进行分片模拟
            if (!queue.isEmpty())
            {
                QByteArray data = queue.dequeue();
                // 分片并打包为IP层数据
                QByteArray raw = ip_slice::pack(slice.fragment(data));

                // 使用文件作为管道则写入文件中
                if (!sync->file.isEmpty())
                {
                    sync->mutex.lock();
                    QFile fio(sync->file);
                    if (fio.open(QIODevice::WriteOnly))
                    {
                        fio.write(raw);
                        fio.close();
                    }
                    sync->mutex.unlock();
                    sync->cond.wakeAll();
                }
                // 写入内存中
                else
                {
                    sync->mem = raw;
                    // 通知重组线程,进行重组
                    sync->cond.wakeAll();
                }
            }
            else
                msleep(100);
        }
    }
};

struct recv_thread : public QThread
{
    volatile bool  flag;
    ip_frag        frag;
    ip_interface  *iface;

    recv_thread(ip_interface *i)
    {
        iface = i;
        flag = true;
        this->start();
    }
    ~recv_thread()
    {
        flag = false;
        iface->sync->cond.wakeAll();
        this->wait(300);
        this->terminate();
    }

    void run() override
    {
        while (flag)
        {
            // 等待是否有重组数据
            iface->sync->mutex.lock();
            iface->sync->cond.wait(&iface->sync->mutex);
            iface->sync->mutex.unlock();

            // 读取IP层数据
            QByteArray raw;
            if (iface->sync->file.isEmpty())
            {
                if (iface->sync->mem.isEmpty())
                    continue;

                raw = iface->sync->mem;
            }
            else
            {
                iface->sync->mutex.lock();
                QFile fio(iface->sync->file);
                if (fio.open(QIODevice::ReadOnly))
                {
                    raw = fio.readAll();
                    fio.close();
                }
                iface->sync->mutex.unlock();
            }

            // 重组数据
            QByteArray buff = frag.reassemble(ip_frag::unpack(raw));
            if (!buff.isEmpty())
                emit iface->recv(buff);
        }
    }
};

ip_interface::ip_interface(const QString &frag_file)
{
    sync = new thread_sync;
    if (!frag_file.isEmpty())
        sync->file = frag_file;

    sthrd = 0;
    rthrd = new recv_thread(this);
}

ip_interface::~ip_interface()
{
    if (rthrd)
        delete rthrd;
    cancel();
}
//!
//! \brief ip_interface::create 根据传输层给出内容，创建一个模拟器
//! \param addr
//! \param protl
//! \param prio
//! \param subf
//! \return
//!
bool ip_interface::create(const QString &addr, IP::Protocol protl,
                          IP::ToSPriority prio, IP::ToSSubfield subf)
{
    if (sthrd)
        return false;
    sthrd = new send_thread(addr, protl, prio, subf);
    sthrd->sync = sync;
    return true;
}
//!
//! \brief ip_interface::cancel 取消模拟器
//!
void ip_interface::cancel()
{
    if (sthrd)
        delete sthrd;
    sthrd = 0;
}

//!
//! \brief ip_interface::send 发送数据
//! \param data
//! \return
//!
bool ip_interface::send(const QByteArray &data)
{
    if (sthrd)
    {
        sthrd->write(data);
        return true;
    }

    return false;
}
