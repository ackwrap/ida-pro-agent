import Foundation
import Network

// URLSession's typed proxy configuration is exposed only through the public
// Swift overlay. Keep credentials on the proxy configuration, never an HTTP
// request header or a shared credential store.
@_cdecl("ida_agent_configure_macos_proxy")
public func configureProxy(
    _ pointer: UnsafeMutableRawPointer,
    _ host: UnsafePointer<CChar>,
    _ port: UInt16,
    _ username: UnsafePointer<CChar>,
    _ password: UnsafePointer<CChar>
) {
    let session = Unmanaged<URLSessionConfiguration>.fromOpaque(pointer).takeUnretainedValue()
    let endpoint = NWEndpoint.hostPort(host: .init(String(cString: host)), port: .init(rawValue: port)!)
    var proxy = ProxyConfiguration(httpCONNECTProxy: endpoint)
    proxy.allowFailover = false
    if username.pointee != 0 {
        proxy.applyCredential(username: String(cString: username), password: String(cString: password))
    }
    session.proxyConfigurations = [proxy]
}
