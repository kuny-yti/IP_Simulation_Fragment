#ifndef IP_HEADER_UI_H
#define IP_HEADER_UI_H

#include <QTableView>
#include <QStandardItemModel>
#include "ip_common.h"

class ip_header_ui : public QTableView
{
    Q_OBJECT
public:
    explicit ip_header_ui(QWidget *parent = 0);
    ~ip_header_ui();

    void set(const IP::DataPackList &dpl);

    void clean();

    void append_part (const IP::DataPack &dpk);

private:
    QStandardItemModel *model;
    uint                rows;
};

#endif // IP_HEADER_UI_H
