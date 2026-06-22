#pragma once

#include "core/Profile.h"
#include "core/Protocol.h"

class QUdpSocket;
class QTimer;

namespace inode {

// H3C / CMCC Portal authentication.
//
// Two sub-dialects are handled:
//   - standard GB/T 28181 (Portal v2) — UDP/2000 by default. Fully on the
//     wire here: REQ_CHALLENGE → ACK_CHALLENGE → REQ_AUTH → ACK_AUTH →
//     AFF_ACK_AUTH, with MD5 checksums keyed on the shared secret.
//   - H3C proprietary TLV extensions — still stubbed. The packet frame
//     lives below but the H3C-specific attribute layout and the H3C
//     "智能感知" challenge machinery are not yet implemented.
//
// The wire format follows the portal-v2 protocol ("Portal 2.0") that H3C
// documents publicly; many iMC/EIA Portal deployments accept a v2 client
// as long as the shared secret matches.
class PortalProtocol : public IProtocol {
    Q_OBJECT
public:
    explicit PortalProtocol(QObject* parent = nullptr);
    ~PortalProtocol() override;

    ProtocolKind kind() const override { return ProtocolKind::Portal; }
    bool isImplemented() const override { return true; }

    void connectWith(const Profile& profile) override;
    void disconnect() override;

private:
    enum class Step { Idle, Challenge, Auth, Affirm, KeepAlive };

    void sendChallenge();
    void sendAuth(const QByteArray& challenge);
    void sendAffirm();
    void sendLogout();
    void onDatagram();
    void onKeepAlive();

    QUdpSocket* m_sock     = nullptr;
    QTimer*     m_keepAlive = nullptr;
    QString     m_host;
    quint16     m_port     = 2000;
    QString     m_secret;
    QString     m_user;
    QString     m_pass;
    QByteArray  m_userIp;     // 4 bytes
    QByteArray  m_userMac;    // 6 bytes (H3C TLV dialect)
    int         m_dialect    = 0;   // 0 = standard v2, 1 = H3C TLV
    quint16     m_serialNo   = 0;
    quint16     m_reqId      = 0;
    Step        m_step       = Step::Idle;
    int         m_retries    = 0;
};

} // namespace inode
