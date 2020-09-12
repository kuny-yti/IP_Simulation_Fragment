#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include "ip_slice.h"
#include "ip_frag.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE
class Widget : public QWidget
{
    Q_OBJECT
public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void on_but_send_clicked();

    void on_but_recv_clicked();

    void on_but_file_clicked();

    void on_but_save_clicked();

    void on_list_ip_doubleClicked(const QModelIndex &index);

    void on_but_compare_clicked();

    void on_rbt_read_file_clicked();

    void on_rbt_read_stack_clicked();

    void on_but_final_save_clicked();

protected:
    void show_data (const QByteArray &data);
private:
    Ui::Widget       *ui;
    ip_slice         slice;
    ip_frag          frag;
    IP::DataPackList stack;
    QByteArray       raw;
    bool             is_read;
};
#endif // WIDGET_H
