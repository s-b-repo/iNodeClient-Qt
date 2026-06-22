#include "EadProtocol.h"

namespace inode {

void EadProtocol::connectWith(const Profile&) {
    emit errorOccurred(tr(
        "Standalone iMC EAD posture (UDP/9019) is not yet implemented — but it is "
        "no longer considered out of reach. Reverse-engineering shows the SEC "
        "posture packet has no real signature: it is sealed only by a hardcoded "
        "keyed-MD5 (seed “SC-EAD_Server$REQ&ShareKey@9019”) and a static XTEA "
        "key, both recovered. A dummy ‘compliant’ posture is therefore "
        "implementable; the remaining work is the result-field schema and the "
        "SEC state machine (START → CHECK_LIST → CHECK_RESULT → SUCCESS → ACL → "
        "heartbeat). See docs/PROTOCOLS.md.\n\n"
        "Supported today: if your gateway only needs the SSL VPN EAD host-check "
        "acknowledgement, use an SSL VPN profile and tick “Send EAD host-check "
        "acknowledgement after login”."));
    setState(ConnectionState::Failed);
}

} // namespace inode
