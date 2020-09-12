#include "ip_header_ui.h"

ip_header_ui::ip_header_ui(QWidget *parent):
    QTableView(parent)
{
    model = new QStandardItemModel(0, IP::HeaderLab.count(), this);
    model->setHorizontalHeaderLabels(IP::HeaderLab);
    this->setModel(model);
    this->setAlternatingRowColors(true);

    rows = 0;
}

ip_header_ui::~ip_header_ui()
{
    clean();
    delete model;
}

void ip_header_ui::clean()
{
    for (uint i = 0; i < rows; ++i)
    {
        QList<QStandardItem*> items = model->takeRow(i);
        foreach (QStandardItem* var, items)
            delete var;
    }
    model->clear();
    model->setHorizontalHeaderLabels(IP::HeaderLab);
    rows = 0;
}
void ip_header_ui::set(const IP::DataPackList &dpl)
{
    clean();
    foreach (const IP::DataPack &var, dpl)
    {
        append_part(var);
    }
}
void ip_header_ui::append_part (const IP::DataPack &dpk)
{
    IP::Header *ip_head = (IP::Header*)dpk.head();

    // 版本
    QStandardItem *item = new QStandardItem(QString::number(ip_head->version));
    item->setData(QVariant(ip_head->version));
    model->setItem(rows, 0, item);

    // 头长度
    item = new QStandardItem(QString::number(ip_head->headlen));
    item->setData(QVariant(ip_head->headlen));
    model->setItem(rows, 1, item);

    // 可靠性
    item = new QStandardItem(QString::number(ip_head->subfield));
    item->setData(QVariant(ip_head->subfield));
    model->setItem(rows, 2, item);

    // 优先级
    item = new QStandardItem(QString::number(ip_head->priority));
    item->setData(QVariant(ip_head->priority));
    model->setItem(rows, 3, item);

    // 总长度
    item = new QStandardItem(QString::number(ip_head->length));
    item->setData(QVariant(ip_head->length));
    model->setItem(rows, 4, item);

    // ID
    item = new QStandardItem(QString::number(ip_head->id));
    item->setData(QVariant(ip_head->id));
    model->setItem(rows, 5, item);

    // 标志
    item = new QStandardItem(QString::number(ip_head->flag));
    item->setData(QVariant(ip_head->flag));
    model->setItem(rows, 6, item);

    // 偏移量
    item = new QStandardItem(QString::number(ip_head->offset));
    item->setData(QVariant(ip_head->offset));
    model->setItem(rows, 7, item);

    // TTL
    item = new QStandardItem(QString::number(ip_head->ttl));
    item->setData(QVariant(ip_head->ttl));
    model->setItem(rows, 8, item);

    // 协议
    item = new QStandardItem(QString::number(ip_head->protocol));
    item->setData(QVariant(ip_head->protocol));
    model->setItem(rows, 9, item);

    // 校验和
    item = new QStandardItem(QString::number(ip_head->checksum));
    item->setData(QVariant(ip_head->checksum));
    model->setItem(rows, 10, item);

    // 源地址
    QString srcaddr(::inet_ntoa(*(struct in_addr*)(&ip_head->addrs))) ;
    item = new QStandardItem(srcaddr);
    item->setData(QVariant(srcaddr));
    model->setItem(rows, 11, item);

    // 目的地址
    QString dstaddr(::inet_ntoa(*(struct in_addr*)(&ip_head->addrd))) ;
    item = new QStandardItem(dstaddr);
    item->setData(QVariant(dstaddr));
    model->setItem(rows, 12, item);

    // 数据
    QByteArray array(dpk.data(), ip_head->length - (ip_head->headlen <<2));
    QString hex = array.toHex(' ');
    item = new QStandardItem(hex);
    item->setData(QVariant(array));
    model->setItem(rows, 13, item);
    ++rows;
}
