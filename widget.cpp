#include "widget.h"
#include "ui_widget.h"
#include <QTime>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget),
      slice(IP::DefaultMTU)
{
    is_read = false;
    slice.set_addr_src(IP::DefaultSourceAddr);
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

// 根据设置进行分片发送还是直接发送
void Widget::on_but_send_clicked()
{
    // 校验MTU是否非法
    QString text = ui->edt_mtu->text();
    int mtu = IP::DefaultMTU;
    for (int i = 0; i < text.count(); ++i)
    {
        QChar c = text.at(i);
        if (c >= '0' && c <= '9')
            continue;
        else
        {
            mtu = -1;
            break;
        }
    }
    if (mtu < 0)
        mtu = IP::DefaultMTU;
    else
        mtu = text.toInt();

    // 设置MTU和目的地址
    slice.set_mtu(mtu);
    slice.set_addr_dst(ui->edt_addr->text());

    // 设置应用协议
    mtu = ui->cbx_type->currentIndex();
    if (mtu == 1)
        slice.set_protocol(IP::Protocol_UDP);
    else
        slice.set_protocol(IP::Protocol_TCP);

    IP::ToSPriority prio = (IP::ToSPriority)ui->cbx_priority->currentIndex();
    IP::ToSSubfield subf = IP::ToS_Normal;
    if (ui->rbt_low_delay->isChecked())
        subf = IP::ToS_LowDelay;
    else if (ui->rbt_high_throughput->isChecked())
        subf = IP::ToS_HighThroughput;
    else if (ui->rbt_high_reliability->isChecked())
        subf = IP::ToS_HighReliability;
    else if (ui->rbt_mincost->isChecked())
        subf = IP::ToS_Mincost;
    slice.set_tos(prio, subf);

    // 取出发送内容
    text = ui->edt_data->toPlainText();
    QByteArray data = text.toUtf8();
    if (ui->rbt_show_hex->isChecked())
        data = QByteArray::fromHex(data);

    // 处理发送内容
    if (ui->rbt_slice->isChecked())
        stack = slice.fragment(data);
    else
        stack = slice.direct(data);

    if (!stack.isEmpty())
    {
        // 呈现栈内容
        ui->list_ip->set(stack);
        QMessageBox::information(NULL, "模拟发送", "模拟发送成功。",
                                 QMessageBox::Yes, QMessageBox::Yes);
    }
}

// 选择要传输的文件
void Widget::on_but_file_clicked()
{
    static bool is_text = true;
    // 修改按钮提示为选择文件发送,此时为输入内容发送
    if (!is_text)
    {
        ui->but_file->setText("选择文件");
        is_text = true;
        return ;
    }

    // 下面选择文件进行发送,同时调整按钮提示切换回输入内容
    QFileDialog *fdia = new QFileDialog(this);
    fdia->setWindowTitle(tr("选择发送内容"));
    fdia->setDirectory(".");
    //fileDialog->setNameFilter(tr("Images(*.png *.jpg *.jpeg *.bmp)"));
    fdia->setFileMode(QFileDialog::ExistingFiles);
    fdia->setViewMode(QFileDialog::Detail);

    QStringList fnl;
    if(fdia->exec())
    {
        fnl = fdia->selectedFiles();
        if (!fnl.isEmpty())
        {
            QFile fio(fnl.at(0));
            if (fio.open(QIODevice::ReadOnly))
            {
                QByteArray data = fio.readAll();
                show_data(data);
                fio.close();
            }
            ui->but_file->setText("关闭文件");
            is_text = false;
        }
    }
}

// 保存协议栈内容
void Widget::on_but_save_clicked()
{
    if (stack.isEmpty())
    {
        QMessageBox::information(NULL, "保存文件", "当前没有需要保存的协议栈内容。",
                                 QMessageBox::Yes, QMessageBox::Yes);
        return ;
    }

    const bool is_text = ui->rbt_save_text->isChecked();
    const bool is_hex  = ui->rbt_save_hex->isChecked();

    QString filter = ("Fragment (*.frag)");
    if (is_text)
        filter = "Visual text (*.txt)";
    else if (is_hex)
        filter = "Hex text (*.hex)";

    QString fn = QFileDialog::getSaveFileName(this,("保存文件"), "./", filter);

    QByteArray data;
    if (!fn.isEmpty())
    {
        if (is_text && !fn.contains(".txt"))
            fn.append(".txt");
        else if (is_hex && !fn.contains(".hex"))
            fn.append(".hex");
        else if (!(is_text || is_hex) && !fn.contains(".frag"))
            fn.append(".frag");

        if (is_text)
        {
            foreach (const IP::DataPack &var, stack)
            {
                QByteArray hdr((char*)var.head(), sizeof(IP::Header));
                data.append(hdr.toHex(' '));
                data.append(' ');
                data.append(var.data(), var.head()->length - sizeof(IP::Header));
                data.append('\n');
            }
        }
        else
        {
            data = ip_slice::pack(stack);
            if (is_hex)
                data = data.toHex(' ');
        }

        if (!data.isEmpty())
        {
            QFile fio(fn);
            if (fio.open(QIODevice::WriteOnly))
            {
                fio.write(data);
                fio.close();
                QMessageBox::information(NULL, "保存文件", QString("保存[%1]成功.").arg(fn),
                                         QMessageBox::Yes, QMessageBox::Yes);
            }
            else
            {
                QMessageBox::information(NULL, "保存文件", QString("打开[%1]文件失败").arg(fn),
                                         QMessageBox::Yes, QMessageBox::Yes);
            }
        }
    }
}

void Widget::on_list_ip_doubleClicked(const QModelIndex &index)
{

}


void Widget::show_data (const QByteArray &data)
{
    static const int show_max = 1024*1024; // 不超过1M文本
    ui->edt_data->clear();

    const int len = data.size() > show_max ? show_max : data.size();

    QByteArray array(data.data(), len);

    if (ui->rbt_show_hex->isChecked())
        ui->edt_data->setText(array.toHex(' '));
    else
        ui->edt_data->setText(QString(array));

}

// 比较分片前和重组后内容是否相同
void Widget::on_but_compare_clicked()
{
    if (is_read)
    {
        QMessageBox::information(NULL, "模拟分片/重组", "比对读取的文件无原始内容作为比较.",
                                 QMessageBox::Yes, QMessageBox::Yes);
        return ;
    }

    QString text = ui->edt_data->toPlainText();
    QByteArray data = text.toUtf8();
    if (ui->rbt_show_hex->isChecked())
        data = QByteArray::fromHex(data);

    if (raw == data)
        QMessageBox::information(NULL, "模拟分片/重组", "比对成功.",
                                 QMessageBox::Yes, QMessageBox::Yes);
    else
        QMessageBox::information(NULL, "模拟分片/重组", "比对失败!",
                                 QMessageBox::Yes, QMessageBox::Yes);
}

// 读取文件作为重组内容
void Widget::on_rbt_read_file_clicked()
{
    QFileDialog *fdia = new QFileDialog(this);
    fdia->setWindowTitle(tr("选择重组文件"));
    fdia->setDirectory(".");
    fdia->setNameFilter(tr("Fragment (*.frag)"));
    fdia->setFileMode(QFileDialog::ExistingFiles);
    fdia->setViewMode(QFileDialog::Detail);

    QStringList fnl;
    if(fdia->exec())
    {
        fnl = fdia->selectedFiles();
        if (!fnl.isEmpty())
            ui->edt_raw_show->setText(fnl.at(0));
    }
}

// 接收数据
void Widget::on_but_recv_clicked()
{
    QString text = "模拟接收成功.";
    QByteArray raw_data;
    QString rawf = ui->edt_raw_show->text();
    if (rawf.contains(".frag"))
    {
        QFile fio(rawf);
        if (fio.open(QIODevice::ReadOnly))
        {
            raw_data = fio.readAll();
            fio.close();
            is_read = true;
        }
        else
        {
            text = "打开[";
            text += rawf;
            text += "]文件失败";
        }
    }
    else
    {
        if (stack.isEmpty())
            text = "栈数据为空!";
        else
            raw_data = ip_slice::pack(stack);
        is_read = false;
    }

    if (!raw_data.isEmpty())
    {
        IP::DataPackList dpl = ip_frag::unpack(raw_data);

        // 呈现栈内容
        ui->list_ip->set(dpl);

        raw = frag.reassemble(dpl);
        if (raw.isEmpty())
            text = "模拟接收失败!";
    }

    QMessageBox::information(NULL, "模拟接收", text,
                             QMessageBox::Yes, QMessageBox::Yes);
}
// 读取协议栈作为重组内容
void Widget::on_rbt_read_stack_clicked()
{
    ui->edt_raw_show->setText("协议栈为输入");
}

// 保存重组后的数据
void Widget::on_but_final_save_clicked()
{
    if (raw.isEmpty())
    {
        QMessageBox::information(NULL, "保存文件", "当前没有需要保存的内容。",
                                 QMessageBox::Yes, QMessageBox::Yes);
        return ;
    }

    const bool is_hex = ui->rbt_final_hex->isChecked();
    const bool is_text = ui->rbt_final_text->isChecked();

    QString filter = ("Raw File (*.raw)");
    if (is_text)
        filter = "Visual text (*.txt)";
    else if (is_hex)
        filter = "Hex text (*.hex)";

    QString fn = QFileDialog::getSaveFileName(this,("保存文件"), "./", filter);
    if (!fn.isEmpty())
    {
        if (is_text && !fn.contains(".txt"))
            fn.append(".txt");
        else if (is_hex && !fn.contains(".hex"))
            fn.append(".hex");
        else if (!(is_text || is_hex) && !fn.contains(".raw"))
            fn.append(".raw");

        QFile fio(fn);
        if (fio.open(QIODevice::WriteOnly))
        {
            if (is_hex)
                fio.write(raw.toHex(' '));
            else
                fio.write(raw);

            fio.close();
            QMessageBox::information(NULL, "保存文件", QString("保存[%1]成功.").arg(fn),
                                     QMessageBox::Yes, QMessageBox::Yes);
        }
        else
        {
            QMessageBox::information(NULL, "保存文件", QString("打开[%1]失败").arg(fn),
                                     QMessageBox::Yes, QMessageBox::Yes);
        }
    }
}
