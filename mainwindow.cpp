#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <pcap.h>
#include <QString>
/*
 * Network kartlarının MAC adreslerini okuyabilmek için
 * Qt'nin sağladığı sınıf.
 */
#include <QNetworkInterface>

#include <QStringList>


/*
 * MAC adresini (AA:BB:CC:DD:EE:FF formatında)
 * 6 byte'lık ham byte dizisine çevirir.
 */

static QByteArray parseMac(const QString& s, bool* ok) {
    QStringList parts = s.trimmed().split(':');

    // MAC adresi 6 parçadan oluşmalı
    if (parts.size() != 6) { if(ok)*ok=false; return {}; }
    QByteArray out; out.reserve(6);

     // hexleri byte yapar
    for (auto &p : parts) {
        bool k=false;
        int v = p.toInt(&k, 16);
        if (!k || v < 0 || v > 255) { if(ok)*ok=false; return {}; }
        out.append(char(v));
    }
    if(ok)*ok=true;
    return out;
}

static bool parseEtherType(QString s, quint16* out) {

    /*
 * EtherType alanını (ör: 88B5)
 * 16bit bir sayıya çevirir
 */
    s = s.trimmed();

      // 0x ile yazılmışsa kaldır
    if (s.startsWith("0x", Qt::CaseInsensitive)) s = s.mid(2);
    bool ok=false;
    uint v = s.toUInt(&ok, 16);
    if(!ok || v > 0xFFFF) return false;
    *out = (quint16)v;
    return true;
}

/*
 * payloadı byte a çevirir.
 */

static QByteArray parseHexPayload(QString s, bool* ok) {
    s = s.trimmed();
    s.remove(' '); s.remove('\n'); s.remove('\r'); s.remove('\t');
    if (s.size() % 2 != 0) { if(ok)*ok=false; return {}; }
    QByteArray out; out.reserve(s.size()/2);
    for (int i=0;i<s.size();i+=2) {
        bool k=false;
        int v = s.mid(i,2).toInt(&k,16);
        if(!k) { if(ok)*ok=false; return {}; }
        out.append(char(v));
    }
    if(ok)*ok=true;
    return out;
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    /*
     * Refresh butonuna basılınca
     * adapter listesini güncelle
     */
    ui->setupUi(this);
    connect(ui->btnrefresh, &QPushButton::clicked,
            this, &MainWindow::refreshAdapters);

     refreshAdapters();
    connect(ui->btnsend, &QPushButton::clicked,
            this, &MainWindow::sendFrame);



}

MainWindow::~MainWindow()
{
    delete ui;
}
void MainWindow::log(const QString& s)
{
    ui->logBox->appendPlainText(s);
}


/*
 * Npcap kullanarak sistemdeki
 * tüm network adapter'ları listeler
 */

void MainWindow::refreshAdapters()
{
    ui->comboAdapter->clear();

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        log(QString("pcap_findalldevs failed: %1").arg(errbuf));
        return;
    }

    int count = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        QString name = d->name ? d->name : "";
        QString desc = d->description ? d->description : "No description";


        ui->comboAdapter->addItem(desc + "  [" + name + "]", name);
        count++;
    }

    pcap_freealldevs(alldevs);
    log(QString("Adapters refreshed. Found: %1").arg(count));
}

/*
 * Auto Src MAC aktifse,
 * seçilen adapter'ın MAC adresini otomatik doldurur
 */


void MainWindow::sendFrame()
{
    QString devName = ui->comboAdapter->currentData().toString();
    if (devName.isEmpty()) { log("No adapter selected."); return; }

    // MAC adreslerini parse et

    bool okDst=false, okSrc=false;
    QByteArray dst = parseMac(ui->editDstMac->text(), &okDst);
    QByteArray src = parseMac(ui->editSrcMac->text(), &okSrc);
    if(!okDst) { log("Invalid Dst MAC."); return; }
    if(!okSrc) { log("Invalid Src MAC."); return; }

     // EtherType oku

    quint16 etherType=0;
    if(!parseEtherType(ui->editEtherType->text(), &etherType)) {
        log("Invalid EtherType.");
        return;
    }

    // Payload oku


    QByteArray payload;
    if (ui->checkHex->isChecked()) {
        bool okP=false;
        payload = parseHexPayload(ui->editPayload->toPlainText(), &okP);
        if(!okP) { log("Invalid HEX payload."); return; }
    } else {
        payload = ui->editPayload->toPlainText().toUtf8();
    }

    // Ethernet payload min 46, max 1500
    if (payload.size() < 46) payload.append(QByteArray(46 - payload.size(), '\0'));
    if (payload.size() > 1500) { log("Payload > 1500 not allowed."); return; }

    // Build Ethernet II frame: [Dst 6][Src 6][EtherType 2][Payload]
    QByteArray frame;
    frame.reserve(14 + payload.size());
    frame.append(dst);
    frame.append(src);
    frame.append(char((etherType >> 8) & 0xFF));
    frame.append(char((etherType     ) & 0xFF));
    frame.append(payload);

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_t* handle = pcap_open_live(devName.toUtf8().constData(), 65536, 1, 1000, errbuf);
    if (!handle) {
        log(QString("pcap_open_live failed: %1").arg(errbuf));
        return;
    }

    int rc = pcap_sendpacket(handle,
                             reinterpret_cast<const u_char*>(frame.constData()),
                             frame.size());

    if (rc != 0) {
        // pcap_geterr handle açıkken çağır
        log(QString("pcap_sendpacket failed: %1").arg(pcap_geterr(handle)));
    } else {
        log(QString("Sent OK. Bytes=%1 EtherType=0x%2")
                .arg(frame.size())
                .arg(QString::number(etherType, 16).toUpper()));
    }

    pcap_close(handle);
}

