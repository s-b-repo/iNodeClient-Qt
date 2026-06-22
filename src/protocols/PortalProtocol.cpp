#include "PortalProtocol.h"

#include "core/CredentialStore.h"
#include "core/Logger.h"
#include "core/NetUtil.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkDatagram>
#include <QNetworkInterface>
#include <QTimer>
#include <QUdpSocket>
#include <QtEndian>

#include <cstring>

// Portal v2 packet layout:
//
//   offset 0  : Version   (1 byte, 0x02)
//   offset 1  : Type      (1 byte: 0x01 REQ_CHALLENGE .. 0x07 AFF_ACK_LOGOUT)
//   offset 2  : AuthType  (1 byte: 0x00 CHAP, 0x01 PAP)
//   offset 3  : Reserved  (1 byte)
//   offset 4  : SerialNo  (2 bytes, big-endian)
//   offset 6  : ReqId     (2 bytes, big-endian)
//   offset 8  : UserIp    (4 bytes)
//   offset 12 : UserPort  (2 bytes, 0)
//   offset 14 : ErrCode   (1 byte)
//   offset 15 : AttrNum   (1 byte)
//   offset 16 : Auth      (16 bytes; MD5 checksum, zeroed while computing)
//   offset 32 : Attributes…

namespace inode {

static constexpr quint8 VERSION   = 0x02;
static constexpr quint8 TYPE_REQ_CHALLENGE = 0x01;
static constexpr quint8 TYPE_ACK_CHALLENGE = 0x02;
static constexpr quint8 TYPE_REQ_AUTH      = 0x03;
static constexpr quint8 TYPE_ACK_AUTH      = 0x04;
static constexpr quint8 TYPE_REQ_LOGOUT    = 0x05;
static constexpr quint8 TYPE_ACK_LOGOUT    = 0x06;
static constexpr quint8 TYPE_AFF_ACK_AUTH  = 0x07;

static constexpr quint8 ATTR_USERNAME      = 0x01;
static constexpr quint8 ATTR_PASSWORD      = 0x02;
static constexpr quint8 ATTR_CHALLENGE     = 0x03;
static constexpr quint8 ATTR_CHAPPASSWORD  = 0x04;
static constexpr quint8 ATTR_TEXTINFO      = 0x05;
static constexpr quint8 ATTR_IPCONFIG      = 0x06;
static constexpr quint8 ATTR_BASEIP        = 0x07;
// H3C proprietary TLV-dialect attributes (beyond the standard 1–7).
static constexpr quint8 ATTR_USERMAC       = 0x0A;   // client MAC (6 bytes)

static QByteArray md5(const QByteArray& in) {
    return QCryptographicHash::hash(in, QCryptographicHash::Md5);
}

static void appendAttr(QByteArray& out, quint8 type, const QByteArray& value) {
    out.append(static_cast<char>(type));
    out.append(static_cast<char>(2 + value.size())); // length includes header
    out.append(value);
}

static QByteArray buildHeader(quint8 type, quint8 authType, quint16 serial, quint16 req,
                              const QByteArray& userIp) {
    QByteArray h(32, '\0');
    h[0] = static_cast<char>(VERSION);
    h[1] = static_cast<char>(type);
    h[2] = static_cast<char>(authType);
    // h[3] reserved
    qToBigEndian<quint16>(serial, reinterpret_cast<uchar*>(h.data()) + 4);
    qToBigEndian<quint16>(req,    reinterpret_cast<uchar*>(h.data()) + 6);
    std::memcpy(h.data() + 8, userIp.constData(), 4);
    // h[12..13] userPort = 0
    // h[14]     errCode
    // h[15]     attrNum (filled later)
    // h[16..31] checksum (zeroed; MD5 computed later over whole packet + secret)
    return h;
}

// The 6-byte hardware address of an interface, for the H3C user-mac TLV.
static QByteArray macFromIface(const QString& iface) {
    QByteArray out;
    const auto all = QNetworkInterface::allInterfaces();
    for (const auto& i : all) {
        if (!iface.isEmpty() && i.name() != iface) continue;
        const QStringList parts = i.hardwareAddress().split(QLatin1Char(':'),
                                                            Qt::SkipEmptyParts);
        if (parts.size() != 6) continue;
        for (const QString& b : parts) out.append(char(b.toUInt(nullptr, 16)));
        break;
    }
    return out;
}

static QByteArray userIpFromLocal(const QString& iface) {
    const QString ip = iface.isEmpty() ? QString() : netutil::primaryIpv4(iface);
    const QHostAddress a(ip.isEmpty() ? QStringLiteral("0.0.0.0") : ip);
    const quint32 raw = a.toIPv4Address();
    QByteArray b(4, '\0');
    qToBigEndian<quint32>(raw, reinterpret_cast<uchar*>(b.data()));
    return b;
}

PortalProtocol::PortalProtocol(QObject* parent) : IProtocol(parent) {}

PortalProtocol::~PortalProtocol() {
    if (m_sock) { m_sock->close(); }
}

void PortalProtocol::connectWith(const Profile& profile) {
    if (profile.serverHost.isEmpty()) {
        emit errorOccurred(tr("Portal requires a server host."));
        setState(ConnectionState::Failed);
        return;
    }
    if (profile.username.isEmpty()) {
        emit errorOccurred(tr("Username is required."));
        setState(ConnectionState::Failed);
        return;
    }
    m_dialect = profile.portalDialect;
    if (m_dialect == 1) {
        m_userMac = macFromIface(profile.iface);
        Logger::instance().info(tr(
            "Portal: H3C TLV dialect (experimental) — appending proprietary "
            "attributes (user-mac%1). Capture a working client if a deployment "
            "needs additional TLVs.").arg(m_userMac.isEmpty() ? tr(" unavailable") : QString()));
    }

    m_host   = profile.serverHost;
    m_port   = profile.serverPort ? profile.serverPort : 2000;
    m_secret = profile.portalSecret.isEmpty() ? QStringLiteral("h3c") : profile.portalSecret;
    m_user   = profile.username;

    QString pw;
    CredentialStore::instance().retrieve(profile.id, &pw);
    if (pw.isEmpty()) {
        emit errorOccurred(tr("No stored password for profile."));
        setState(ConnectionState::Failed);
        return;
    }
    m_pass = pw;
    m_userIp = userIpFromLocal(profile.iface);
    m_serialNo = static_cast<quint16>(QDateTime::currentSecsSinceEpoch() & 0xffffu);
    m_reqId = 0;
    m_retries = 0;

    m_sock = new QUdpSocket(this);
    if (!m_sock->bind(QHostAddress::AnyIPv4, 0)) {
        emit errorOccurred(tr("Portal: failed to bind UDP socket: %1").arg(m_sock->errorString()));
        setState(ConnectionState::Failed);
        return;
    }
    connect(m_sock, &QUdpSocket::readyRead, this, &PortalProtocol::onDatagram);

    setState(ConnectionState::Connecting);
    sendChallenge();
}

void PortalProtocol::sendChallenge() {
    m_step = Step::Challenge;
    QByteArray pkt = buildHeader(TYPE_REQ_CHALLENGE, 0x00, m_serialNo, m_reqId, m_userIp);
    pkt[15] = 0; // attrNum

    // Portal v2 uses a trailing checksum over (packet || secret) in slot 16..31.
    // For REQ_CHALLENGE the "Auth" field is typically zeroed; we still MD5 to
    // populate it as some iMC builds validate REQ_CHALLENGE too.
    QByteArray forHash = pkt + m_secret.toUtf8();
    std::memcpy(pkt.data() + 16, md5(forHash).constData(), 16);

    Logger::instance().info(tr("Portal: REQ_CHALLENGE → %1:%2").arg(m_host).arg(m_port));
    const auto addr = QHostInfo::fromName(m_host).addresses().value(0, QHostAddress(m_host));
    m_sock->writeDatagram(pkt, addr, m_port);
    setState(ConnectionState::Authenticating);
}

void PortalProtocol::sendAuth(const QByteArray& challenge) {
    m_step = Step::Auth;
    ++m_reqId;

    // Compute CHAP password = MD5(ReqId || password || challenge), 16 bytes.
    QByteArray forChap;
    forChap.append(static_cast<char>(m_reqId & 0xff));
    forChap.append(m_pass.toUtf8());
    forChap.append(challenge);
    const QByteArray chapPw = md5(forChap);

    QByteArray pkt = buildHeader(TYPE_REQ_AUTH, 0x00 /* CHAP */, m_serialNo, m_reqId, m_userIp);

    QByteArray attrs;
    quint8 attrNum = 2;
    appendAttr(attrs, ATTR_USERNAME, m_user.toUtf8());
    appendAttr(attrs, ATTR_CHAPPASSWORD, chapPw);
    // H3C TLV dialect: append the proprietary client-MAC attribute.
    if (m_dialect == 1 && m_userMac.size() == 6) {
        appendAttr(attrs, ATTR_USERMAC, m_userMac);
        ++attrNum;
    }
    pkt[15] = static_cast<char>(attrNum); // attrNum

    QByteArray full = pkt + attrs;
    // checksum = MD5(packet-with-zero-auth || attrs || secret)
    QByteArray forHash = full + m_secret.toUtf8();
    std::memcpy(full.data() + 16, md5(forHash).constData(), 16);

    Logger::instance().info(tr("Portal: REQ_AUTH user='%1' reqId=%2").arg(m_user).arg(m_reqId));
    const auto addr = QHostInfo::fromName(m_host).addresses().value(0, QHostAddress(m_host));
    m_sock->writeDatagram(full, addr, m_port);
}

void PortalProtocol::sendAffirm() {
    QByteArray pkt = buildHeader(TYPE_AFF_ACK_AUTH, 0x00, m_serialNo, m_reqId, m_userIp);
    pkt[15] = 0;
    QByteArray forHash = pkt + m_secret.toUtf8();
    std::memcpy(pkt.data() + 16, md5(forHash).constData(), 16);
    const auto addr = QHostInfo::fromName(m_host).addresses().value(0, QHostAddress(m_host));
    m_sock->writeDatagram(pkt, addr, m_port);
    Logger::instance().info(QStringLiteral("Portal: AFF_ACK_AUTH sent"));
}

void PortalProtocol::sendLogout() {
    if (!m_sock) return;
    ++m_reqId;
    QByteArray pkt = buildHeader(TYPE_REQ_LOGOUT, 0x00, m_serialNo, m_reqId, m_userIp);
    pkt[15] = 0;
    QByteArray forHash = pkt + m_secret.toUtf8();
    std::memcpy(pkt.data() + 16, md5(forHash).constData(), 16);
    const auto addr = QHostInfo::fromName(m_host).addresses().value(0, QHostAddress(m_host));
    m_sock->writeDatagram(pkt, addr, m_port);
    Logger::instance().info(QStringLiteral("Portal: REQ_LOGOUT sent"));
}

void PortalProtocol::onDatagram() {
    while (m_sock && m_sock->hasPendingDatagrams()) {
        const auto dg = m_sock->receiveDatagram();
        const QByteArray data = dg.data();
        if (data.size() < 32) { Logger::instance().warn(QStringLiteral("Portal: short packet")); continue; }
        const quint8 type = static_cast<quint8>(data.at(1));
        const quint8 err  = static_cast<quint8>(data.at(14));

        if (type == TYPE_ACK_CHALLENGE) {
            if (err != 0) {
                emit errorOccurred(tr("Portal: challenge rejected (code %1)").arg(err));
                setState(ConnectionState::Failed);
                return;
            }
            // Extract challenge attribute.
            int off = 32;
            QByteArray challenge;
            while (off + 2 <= data.size()) {
                const quint8 t = static_cast<quint8>(data.at(off));
                const quint8 l = static_cast<quint8>(data.at(off + 1));
                if (l < 2 || off + l > data.size()) break;
                if (t == ATTR_CHALLENGE) challenge = data.mid(off + 2, l - 2);
                off += l;
            }
            if (challenge.isEmpty()) {
                emit errorOccurred(tr("Portal: ACK_CHALLENGE contained no challenge attribute"));
                setState(ConnectionState::Failed);
                return;
            }
            sendAuth(challenge);
        } else if (type == TYPE_ACK_AUTH) {
            if (err != 0) {
                emit errorOccurred(tr("Portal: auth rejected (code %1)").arg(err));
                setState(ConnectionState::Failed);
                return;
            }
            sendAffirm();

            ConnectionStats s;
            s.iface       = QString();
            s.localIp     = QHostAddress(qFromBigEndian<quint32>(m_userIp.constData())).toString();
            s.connectedAt = QDateTime::currentDateTime();
            setStats(s);
            setState(ConnectionState::Connected);

            // Start a minute-ish keep-alive so iMC doesn't age the session out.
            if (!m_keepAlive) {
                m_keepAlive = new QTimer(this);
                m_keepAlive->setInterval(45 * 1000);
                connect(m_keepAlive, &QTimer::timeout, this, &PortalProtocol::onKeepAlive);
            }
            m_keepAlive->start();
            m_step = Step::KeepAlive;
        } else if (type == TYPE_ACK_LOGOUT) {
            Logger::instance().info(QStringLiteral("Portal: ACK_LOGOUT"));
            if (m_keepAlive) m_keepAlive->stop();
            setState(ConnectionState::Disconnected);
        }
    }
}

void PortalProtocol::onKeepAlive() {
    // Portal v2 doesn't mandate a dedicated keep-alive packet; re-sending the
    // affirm keeps NAT mappings open and lets us detect a dropped server.
    sendAffirm();
}

void PortalProtocol::disconnect() {
    if (!m_sock) return;
    setState(ConnectionState::Disconnecting);
    if (m_keepAlive) m_keepAlive->stop();
    sendLogout();
    // Give the server a moment to reply; then tear down regardless.
    QTimer::singleShot(1500, this, [this] {
        if (m_sock) { m_sock->close(); m_sock->deleteLater(); m_sock = nullptr; }
        setState(ConnectionState::Disconnected);
    });
}

} // namespace inode
